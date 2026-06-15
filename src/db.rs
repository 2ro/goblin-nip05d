// Shared application state and the SQLite layer.
//
// `App` is the single piece of state handed to every handler: the database
// connection, the in-memory rate/cooldown maps, and the resolved config. The
// schema is a const so tests can stand up an identical in-memory database.

use crate::config::Config;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::{
    collections::HashMap,
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
        ON names(pubkey) WHERE released_at IS NULL;";

pub struct App {
    pub db: Mutex<Connection>,
    pub rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// Seen NIP-98 auth event ids (one-time use within the freshness window).
    pub seen_auth: Mutex<HashMap<String, Instant>>,
    /// Resolved runtime config.
    pub cfg: Config,
}

impl App {
    /// Open the database at `cfg.db_path`, applying the schema. Pass a
    /// `:memory:` db path for tests.
    pub fn open(cfg: Config) -> Self {
        let db = Connection::open(&cfg.db_path).expect("open sqlite db");
        // WAL lets the readers (availability/well-known) proceed concurrently
        // with the single writer instead of serializing on one lock.
        let _ = db.pragma_update(None, "journal_mode", "WAL");
        let _ = db.busy_timeout(Duration::from_secs(5));
        db.execute_batch(SCHEMA).expect("init schema");
        App {
            db: Mutex::new(db),
            rate: Mutex::new(HashMap::new()),
            seen_auth: Mutex::new(HashMap::new()),
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
