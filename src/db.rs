// Shared application state and the SQLite layer.
//
// `App` is the single piece of state handed to every handler: the database
// connection, the in-memory rate/cooldown maps, the avatar directory, and the
// resolved config. The schema is a const so tests can stand up an identical
// in-memory database.

use crate::config::Config;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

/// The full schema. Idempotent (`IF NOT EXISTS`), so it doubles as the
/// migration applied at every startup.
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS names (
        name TEXT PRIMARY KEY,
        pubkey TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        released_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_names_pubkey ON names(pubkey);
    -- Enforce one active name per pubkey at the DB layer (defeats the
    -- check-then-insert race that app code alone cannot close).
    CREATE UNIQUE INDEX IF NOT EXISTS idx_active_pubkey
        ON names(pubkey) WHERE released_at IS NULL;
    CREATE TABLE IF NOT EXISTS avatars (
        name TEXT PRIMARY KEY,
        hash TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
    -- DB-backed daily change log: survives restarts, unlike the
    -- in-memory limiter.
    CREATE TABLE IF NOT EXISTS avatar_changes (
        name TEXT NOT NULL,
        changed_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_avatar_changes
        ON avatar_changes(name, changed_at);";

pub struct App {
    pub db: Mutex<Connection>,
    pub rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// Seen NIP-98 auth event ids (one-time use within the freshness window).
    pub seen_auth: Mutex<HashMap<String, Instant>>,
    /// Directory holding processed avatar PNGs, named by content hash.
    pub avatar_dir: PathBuf,
    /// Resolved runtime config.
    pub cfg: Config,
}

impl App {
    /// Open the database at `cfg.db_path`, applying the schema, and create the
    /// avatar directory (when configured). Pass a `:memory:` db path for tests.
    pub fn open(cfg: Config) -> Self {
        let db = Connection::open(&cfg.db_path).expect("open sqlite db");
        // WAL lets the readers (availability/well-known) proceed concurrently
        // with the single writer instead of serializing on one lock.
        let _ = db.pragma_update(None, "journal_mode", "WAL");
        let _ = db.busy_timeout(Duration::from_secs(5));
        db.execute_batch(SCHEMA).expect("init schema");
        let avatar_dir = PathBuf::from(&cfg.avatar_dir);
        if !cfg.avatar_dir.is_empty() {
            std::fs::create_dir_all(&avatar_dir).expect("create avatar dir");
        }
        App {
            db: Mutex::new(db),
            rate: Mutex::new(HashMap::new()),
            seen_auth: Mutex::new(HashMap::new()),
            avatar_dir,
            cfg,
        }
    }

    /// Active (non-released) pubkey for a name.
    pub fn lookup(&self, name: &str) -> Option<String> {
        self.db
            .lock()
            .query_row(
                "SELECT pubkey FROM names WHERE name = ?1 AND released_at IS NULL",
                [name],
                |r| r.get::<_, String>(0),
            )
            .ok()
    }

    /// Active name owned by a pubkey.
    pub fn name_of(&self, pubkey: &str) -> Option<String> {
        self.db
            .lock()
            .query_row(
                "SELECT name FROM names WHERE pubkey = ?1 AND released_at IS NULL",
                [pubkey],
                |r| r.get::<_, String>(0),
            )
            .ok()
    }

    /// Stored avatar content hash for a name, if any.
    pub fn avatar_hash(&self, name: &str) -> Option<String> {
        self.db
            .lock()
            .query_row("SELECT hash FROM avatars WHERE name = ?1", [name], |r| {
                r.get::<_, String>(0)
            })
            .ok()
    }

    /// Drop a name's avatar row and unlink its file unless another name
    /// still references the same content hash (uploads are deduplicated by
    /// content, so files are refcounted).
    pub fn purge_avatar(&self, name: &str) {
        let mut guard = self.db.lock();
        let tx = match guard.transaction() {
            Ok(t) => t,
            Err(_) => return,
        };
        let hash: Option<String> = tx
            .query_row("SELECT hash FROM avatars WHERE name = ?1", [name], |r| {
                r.get(0)
            })
            .ok();
        let Some(hash) = hash else {
            return;
        };
        let _ = tx.execute("DELETE FROM avatars WHERE name = ?1", [name]);
        let still_used: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM avatars WHERE hash = ?1",
                [&hash],
                |r| r.get(0),
            )
            .unwrap_or(1);
        if tx.commit().is_ok() && still_used == 0 {
            let _ = std::fs::remove_file(self.avatar_dir.join(format!("{hash}.png")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transfer UPDATE's invariants at the SQL layer: owner-guarded swap,
    /// no-op on wrong owner, and the partial-unique pubkey index rejecting a
    /// target key that already holds an active name.
    #[test]
    fn transfer_sql_invariants() {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(SCHEMA).unwrap();
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        db.execute(
            "INSERT INTO names (name, pubkey, created_at) VALUES ('alice', ?1, 1)",
            rusqlite::params![a],
        )
        .unwrap();

        let xfer = "UPDATE names SET pubkey = ?3 \
                    WHERE name = ?1 AND pubkey = ?2 AND released_at IS NULL";

        // Wrong owner: guarded update touches nothing.
        let n = db.execute(xfer, rusqlite::params!["alice", b, c]).unwrap();
        assert_eq!(n, 0);

        // Owner swap succeeds and the mapping moves.
        let n = db.execute(xfer, rusqlite::params!["alice", a, b]).unwrap();
        assert_eq!(n, 1);
        let owner: String = db
            .query_row("SELECT pubkey FROM names WHERE name='alice'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(owner, b);

        // Target already holding an active name is rejected by the index.
        db.execute(
            "INSERT INTO names (name, pubkey, created_at) VALUES ('carol', ?1, 1)",
            rusqlite::params![c],
        )
        .unwrap();
        let res = db.execute(xfer, rusqlite::params!["alice", b, c]);
        match res {
            Err(rusqlite::Error::SqliteFailure(e, _)) => {
                assert_eq!(e.code, rusqlite::ErrorCode::ConstraintViolation)
            }
            other => panic!("expected constraint violation, got {:?}", other),
        }
        let owner: String = db
            .query_row("SELECT pubkey FROM names WHERE name='alice'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(owner, b);
    }

    /// The ownership-gated avatar upsert: writes for the active owner,
    /// touches nothing once the name is released or owned by another key.
    #[test]
    fn avatar_upsert_requires_active_ownership() {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(SCHEMA).unwrap();
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        db.execute(
            "INSERT INTO names (name, pubkey, created_at) VALUES ('alice', ?1, 1)",
            rusqlite::params![a],
        )
        .unwrap();
        let upsert = "INSERT INTO avatars (name, hash, updated_at)
             SELECT ?1, ?2, ?3 WHERE EXISTS(
                SELECT 1 FROM names
                WHERE name = ?1 AND pubkey = ?4 AND released_at IS NULL)
             ON CONFLICT(name) DO UPDATE SET
                hash = excluded.hash, updated_at = excluded.updated_at";

        let n = db
            .execute(upsert, rusqlite::params!["alice", "h1", 1, a])
            .unwrap();
        assert_eq!(n, 1);
        let n = db
            .execute(upsert, rusqlite::params!["alice", "h2", 2, b])
            .unwrap();
        assert_eq!(n, 0);
        let n = db
            .execute(upsert, rusqlite::params!["alice", "h3", 3, a])
            .unwrap();
        assert_eq!(n, 1);
        let h: String = db
            .query_row("SELECT hash FROM avatars WHERE name='alice'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(h, "h3");
        db.execute("UPDATE names SET released_at = 9 WHERE name='alice'", [])
            .unwrap();
        let n = db
            .execute(upsert, rusqlite::params!["alice", "h4", 4, a])
            .unwrap();
        assert_eq!(n, 0);
    }

    /// Content-hash files are shared; the refcount query keeps a file that
    /// another name still points at.
    #[test]
    fn avatar_hash_refcount() {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(SCHEMA).unwrap();
        db.execute_batch(
            "INSERT INTO avatars VALUES ('alice', 'same', 1);
             INSERT INTO avatars VALUES ('bob', 'same', 1);",
        )
        .unwrap();
        db.execute("DELETE FROM avatars WHERE name='alice'", [])
            .unwrap();
        let still: i64 = db
            .query_row("SELECT COUNT(*) FROM avatars WHERE hash='same'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(still, 1, "shared hash must survive one name's deletion");
    }

    /// The rolling-24h change counter: 5 changes pass, the 6th is denied.
    #[test]
    fn avatar_daily_window() {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(SCHEMA).unwrap();
        let now = 1_000_000i64;
        let per_day = 5i64;
        for i in 0..per_day {
            db.execute(
                "INSERT INTO avatar_changes VALUES ('alice', ?1)",
                [now - i * 100],
            )
            .unwrap();
        }
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM avatar_changes WHERE name='alice' AND changed_at > ?1",
                [now - 86_400],
                |r| r.get(0),
            )
            .unwrap();
        assert!(count >= per_day, "6th change must be denied");
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM avatar_changes WHERE name='alice' AND changed_at > ?1",
                [now + 90_000 - 86_400],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    /// A released name is immediately revivable by a new key via the register
    /// upsert.
    #[test]
    fn released_name_immediately_reclaimable() {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(SCHEMA).unwrap();
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        db.execute(
            "INSERT INTO names (name, pubkey, created_at, released_at) VALUES ('alice', ?1, 1, 5)",
            rusqlite::params![a],
        )
        .unwrap();
        let n = db
            .execute(
                "INSERT INTO names (name, pubkey, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(name) DO UPDATE SET pubkey = excluded.pubkey,
                    created_at = excluded.created_at, released_at = NULL
                 WHERE names.released_at IS NOT NULL",
                rusqlite::params!["alice", b, 6],
            )
            .unwrap();
        assert_eq!(n, 1);
        let owner: String = db
            .query_row(
                "SELECT pubkey FROM names WHERE name='alice' AND released_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(owner, b);
    }
}
