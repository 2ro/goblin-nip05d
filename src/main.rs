// goblin-nip05d — NIP-05 identity service for the Goblin wallet (goblin.st).
//
// Endpoints:
//   GET    /.well-known/nostr.json?name=<name>   NIP-05 resolution (CORS *)
//   GET    /api/v1/name/{name}                   availability check
//   POST   /api/v1/register                      {name, pubkey} + NIP-98 auth
//   DELETE /api/v1/register/{name}               NIP-98 auth by owner
//   GET    /api/v1/health                        liveness
//   GET    /                                     landing page

mod avatar;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::Engine;
use nostr::{Event, JsonUtil, Kind, Timestamp};
use parking_lot::Mutex;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BIND_ADDR: &str = "127.0.0.1:8191";
/// Minimum spacing between successful name changes (register or release)
/// per pubkey — spam brake. In-memory: restarts reset it, which is fine.
const NAME_CHANGE_COOLDOWN: Duration = Duration::from_secs(600);
const BASE_URL: &str = "https://goblin.st";
const DOMAIN: &str = "goblin.st";
const RELAYS: &[&str] = &["wss://nrelay.us-ea.st"];
const NAME_MIN: usize = 3;
const NAME_MAX: usize = 30;
const AUTH_MAX_AGE_SECS: i64 = 60;
/// Avatar changes allowed per name per rolling 24h window.
const AVATAR_CHANGES_PER_DAY: i64 = 5;

const RESERVED: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "goblin",
    "goblins",
    "support",
    "help",
    "info",
    "mail",
    "email",
    "www",
    "relay",
    "nrelay",
    "nostr",
    "pay",
    "payment",
    "payments",
    "wallet",
    "grin",
    "mimblewimble",
    "official",
    "security",
    "abuse",
    "postmaster",
    "hostmaster",
    "webmaster",
    "contact",
    "team",
    "staff",
    "mod",
    "moderator",
    "moderators",
    "system",
    "bot",
    "api",
    "app",
    "dev",
    "developer",
    "test",
    "testing",
    "anonymous",
    "anon",
    "null",
    "void",
    "owner",
    "ceo",
    "register",
    "registration",
    "account",
    "accounts",
    "verify",
    "verified",
    "billing",
    "donate",
    "treasury",
    "faucet",
    "exchange",
    "swap",
    "bank",
    "money",
    "cash",
    "fees",
    "fee",
    "node",
    "miner",
    "mining",
    "explorer",
    "status",
    "blog",
    "news",
    "docs",
    "wiki",
    "store",
    "shop",
];

struct App {
    db: Mutex<Connection>,
    rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// Seen NIP-98 auth event ids (one-time use within the freshness window).
    seen_auth: Mutex<HashMap<String, Instant>>,
    /// Directory holding processed avatar PNGs, named by content hash.
    avatar_dir: PathBuf,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn valid_name(name: &str) -> bool {
    let len = name.chars().count();
    if !(NAME_MIN..=NAME_MAX).contains(&len) {
        return false;
    }
    // ASCII lowercase alphanumerics plus . _ - ; must start and end alphanumeric.
    let bytes = name.as_bytes();
    let ok_char =
        |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-');
    if !bytes.iter().all(|&c| ok_char(c)) {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && (last.is_ascii_lowercase() || last.is_ascii_digit())
}

/// Fold a name to catch separator/digit look-alikes of reserved terms, so
/// `g0blin`, `g-o-b-l-i-n` and `supp0rt` can't impersonate `goblin`/`support`
/// as payment identities. Conservative: a name is only blocked when its folded
/// form exactly equals a reserved term's folded form (so `goblinfan` stays free).
fn fold_lookalike(name: &str) -> String {
    name.chars()
        .filter_map(|c| match c {
            '.' | '_' | '-' => None,
            '0' => Some('o'),
            '1' => Some('i'),
            '3' => Some('e'),
            '4' => Some('a'),
            '5' => Some('s'),
            '7' => Some('t'),
            '8' => Some('b'),
            '9' => Some('g'),
            c => Some(c),
        })
        .collect()
}

/// True when `name` is reserved outright or folds onto a reserved term.
fn is_reserved(name: &str) -> bool {
    if RESERVED.contains(&name) {
        return true;
    }
    let folded = fold_lookalike(name);
    RESERVED.iter().any(|r| fold_lookalike(r) == folded)
}

fn valid_pubkey_hex(pk: &str) -> bool {
    pk.len() == 64
        && pk
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

impl App {
    fn open(db_path: &str, avatar_dir: PathBuf) -> Self {
        let db = Connection::open(db_path).expect("open sqlite db");
        // WAL lets the readers (availability/well-known) proceed concurrently
        // with the single writer instead of serializing on one lock.
        let _ = db.pragma_update(None, "journal_mode", "WAL");
        let _ = db.busy_timeout(Duration::from_secs(5));
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS names (
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
                ON avatar_changes(name, changed_at);",
        )
        .expect("init schema");
        std::fs::create_dir_all(&avatar_dir).expect("create avatar dir");
        App {
            db: Mutex::new(db),
            rate: Mutex::new(HashMap::new()),
            seen_auth: Mutex::new(HashMap::new()),
            avatar_dir,
        }
    }

    /// Record a NIP-98 auth event id as used; returns false if already seen
    /// within the freshness window (replay).
    fn auth_event_fresh(&self, event_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(AUTH_MAX_AGE_SECS as u64 + 5);
        let mut seen = self.seen_auth.lock();
        seen.retain(|_, t| now.duration_since(*t) < window);
        if seen.contains_key(event_id) {
            return false;
        }
        seen.insert(event_id.to_string(), now);
        true
    }

    /// True when an operation in this bucket happened within the window.
    /// Check-only — pair with [`Self::record_op`] on success, so failed
    /// attempts (taken name, bad auth) never burn the caller's cooldown.
    fn cooldown_active(&self, bucket: &str, key: &str, window: Duration) -> bool {
        let k = format!("{bucket}:{key}");
        let now = Instant::now();
        let mut map = self.rate.lock();
        if let Some(hits) = map.get_mut(&k) {
            hits.retain(|t| now.duration_since(*t) < window);
            return !hits.is_empty();
        }
        false
    }

    /// Record a completed operation for cooldown tracking.
    fn record_op(&self, bucket: &str, key: &str) {
        let k = format!("{bucket}:{key}");
        self.rate.lock().entry(k).or_default().push(Instant::now());
    }

    /// Sliding-window in-memory rate limiter. Returns true when the call is allowed.
    fn allow(&self, bucket: &str, ip: &str, max: usize, window: Duration) -> bool {
        let key = format!("{bucket}:{ip}");
        let now = Instant::now();
        let mut map = self.rate.lock();
        let hits = map.entry(key).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= max {
            return false;
        }
        hits.push(now);
        // Opportunistic global cleanup to bound memory.
        if map.len() > 50_000 {
            map.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < window));
        }
        true
    }

    /// Active (non-released) pubkey for a name.
    fn lookup(&self, name: &str) -> Option<String> {
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
    fn name_of(&self, pubkey: &str) -> Option<String> {
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
    fn avatar_hash(&self, name: &str) -> Option<String> {
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
    fn purge_avatar(&self, name: &str) {
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

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Verify a NIP-98 `Authorization: Nostr <base64-event>` header.
/// Returns the authenticated pubkey hex on success.
/// On success returns (authenticated pubkey hex, auth event id hex).
fn verify_nip98(
    headers: &HeaderMap,
    method: &Method,
    url_path: &str,
    body: &[u8],
) -> Result<(String, String), (StatusCode, String)> {
    let unauthorized = |msg: &str| (StatusCode::UNAUTHORIZED, msg.to_string());

    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized("missing Authorization header"))?;
    let b64 = auth
        .strip_prefix("Nostr ")
        .ok_or_else(|| unauthorized("Authorization scheme must be Nostr"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| unauthorized("invalid base64 auth event"))?;
    let event = Event::from_json(&raw).map_err(|_| unauthorized("invalid auth event json"))?;
    event
        .verify()
        .map_err(|_| unauthorized("bad event signature"))?;

    if event.kind != Kind::HttpAuth {
        return Err(unauthorized("auth event kind must be 27235"));
    }
    let now = Timestamp::now();
    let age = (now.as_u64() as i64) - (event.created_at.as_u64() as i64);
    // Allow modest backward skew but only a few seconds forward, to bound the
    // replay window (paired with one-time event-id enforcement at the caller).
    if age > AUTH_MAX_AGE_SECS || age < -5 {
        return Err(unauthorized("auth event expired or post-dated"));
    }

    let mut u_ok = false;
    let mut method_ok = false;
    let mut payload_hash: Option<String> = None;
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(|s| s.as_str()) {
            Some("u") => {
                if let Some(u) = parts.get(1) {
                    let expected = format!("{BASE_URL}{url_path}");
                    let normalized = u.trim_end_matches('/');
                    u_ok = normalized == expected.trim_end_matches('/');
                }
            }
            Some("method") => {
                if let Some(m) = parts.get(1) {
                    method_ok = m.eq_ignore_ascii_case(method.as_str());
                }
            }
            Some("payload") => {
                payload_hash = parts.get(1).cloned();
            }
            _ => {}
        }
    }
    if !u_ok {
        return Err(unauthorized("auth event url mismatch"));
    }
    if !method_ok {
        return Err(unauthorized("auth event method mismatch"));
    }
    if let Some(expect) = payload_hash {
        let got = hex::encode(Sha256::digest(body));
        if !expect.eq_ignore_ascii_case(&got) {
            return Err(unauthorized("auth event payload hash mismatch"));
        }
    } else if !body.is_empty() {
        return Err(unauthorized("auth event missing payload hash"));
    }

    Ok((event.pubkey.to_hex(), event.id.to_hex()))
}

#[derive(Deserialize)]
struct WellKnownParams {
    name: Option<String>,
}

async fn well_known(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(params): Query<WellKnownParams>,
) -> Response {
    if !app.allow("read", &client_ip(&headers), 120, Duration::from_secs(60)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let mut names = serde_json::Map::new();
    let mut relays = serde_json::Map::new();
    if let Some(name) = params.name.map(|n| n.to_lowercase()) {
        if valid_name(&name) {
            if let Some(pk) = app.lookup(&name) {
                names.insert(name, json!(pk.clone()));
                relays.insert(pk, json!(RELAYS));
            }
        }
    }
    let body = json!({ "names": names, "relays": relays });
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

async fn availability(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !app.allow("read", &client_ip(&headers), 120, Duration::from_secs(60)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name) {
        return (
            StatusCode::OK,
            Json(json!({"name": name, "available": false, "reason": "invalid"})),
        )
            .into_response();
    }
    if is_reserved(&name) {
        return (
            StatusCode::OK,
            Json(json!({"name": name, "available": false, "reason": "reserved"})),
        )
            .into_response();
    }
    if app.lookup(&name).is_some() {
        return (
            StatusCode::OK,
            Json(json!({"name": name, "available": false, "reason": "taken"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(json!({"name": name, "available": true})),
    )
        .into_response()
}

#[derive(Deserialize)]
struct RegisterBody {
    name: String,
    pubkey: String,
}

async fn register(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow("reg", &ip, 10, Duration::from_secs(3600)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }

    let (auth_pubkey, auth_id) =
        match verify_nip98(&headers, &Method::POST, "/api/v1/register", &body) {
            Ok(v) => v,
            Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
        };
    if !app.auth_event_fresh(&auth_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth event replayed"})),
        )
            .into_response();
    }

    // One name change (register or release) per pubkey per 10 minutes:
    // checked after auth so strangers can't burn someone's budget, recorded
    // only on success so failed attempts don't lock the user out.
    if app.cooldown_active("namechange", &auth_pubkey, NAME_CHANGE_COOLDOWN) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "name_change_cooldown"})),
        )
            .into_response();
    }

    let req: RegisterBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid body"})),
            )
                .into_response()
        }
    };
    let name = req.name.to_lowercase();
    let pubkey = req.pubkey.to_lowercase();

    if !valid_pubkey_hex(&pubkey) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid pubkey"})),
        )
            .into_response();
    }
    if pubkey != auth_pubkey {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth pubkey does not match body pubkey"})),
        )
            .into_response();
    }
    if !valid_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid name"})),
        )
            .into_response();
    }
    if is_reserved(&name) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "name reserved"})),
        )
            .into_response();
    }

    // Existing active registration of this exact name.
    if let Some(owner) = app.lookup(&name) {
        if owner == pubkey {
            return (
                StatusCode::OK,
                Json(json!({"name": name, "nip05": format!("{name}@{DOMAIN}")})),
            )
                .into_response();
        }
        return (StatusCode::CONFLICT, Json(json!({"error": "name taken"}))).into_response();
    }
    // One active name per pubkey.
    if let Some(existing) = app.name_of(&pubkey) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "pubkey already has a name", "name": existing})),
        )
            .into_response();
    }

    // INSERT guarded by the name PRIMARY KEY and the partial-unique pubkey
    // index. The ON CONFLICT(name) only revives a released name; a concurrent
    // double-register (same pubkey, different names) is caught by the unique
    // pubkey index and surfaces as a constraint error → 409.
    let res = app.db.lock().execute(
        "INSERT INTO names (name, pubkey, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO UPDATE SET pubkey = excluded.pubkey,
            created_at = excluded.created_at, released_at = NULL
         WHERE names.released_at IS NOT NULL",
        rusqlite::params![name, pubkey, unix_now()],
    );
    match res {
        // rows == 0 means the ON CONFLICT no-op fired (name already active):
        // not acquired, report a conflict rather than a false success.
        Ok(0) => (StatusCode::CONFLICT, Json(json!({"error": "name taken"}))).into_response(),
        Ok(_) => {
            tracing::info!("registered {name} -> {pubkey}");
            app.record_op("namechange", &pubkey);
            (
                StatusCode::CREATED,
                Json(json!({"name": name, "nip05": format!("{name}@{DOMAIN}")})),
            )
                .into_response()
        }
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            // The partial-unique pubkey index rejected a second active name.
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "pubkey already has a name"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("db insert failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "db error"})),
            )
                .into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct TransferBody {
    name: String,
    new_pubkey: String,
}

/// POST /api/v1/transfer — atomically re-point an owned, active name to a
/// new pubkey. NIP-98 signed by the CURRENT owner key; the new pubkey must
/// not hold an active name. Built for client key rotation so @names survive.
async fn transfer(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow("xfer", &ip, 10, Duration::from_secs(3600)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }

    let (auth_pubkey, auth_id) =
        match verify_nip98(&headers, &Method::POST, "/api/v1/transfer", &body) {
            Ok(v) => v,
            Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
        };
    if !app.auth_event_fresh(&auth_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth event replayed"})),
        )
            .into_response();
    }

    let req: TransferBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid body"})),
            )
                .into_response()
        }
    };
    let name = req.name.to_lowercase();
    let new_pubkey = req.new_pubkey.to_lowercase();

    if !valid_pubkey_hex(&new_pubkey) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid new pubkey"})),
        )
            .into_response();
    }
    if new_pubkey == auth_pubkey {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "new pubkey equals current owner"})),
        )
            .into_response();
    }
    if !valid_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid name"})),
        )
            .into_response();
    }

    // The auth key must own the active name.
    match app.lookup(&name) {
        Some(owner) if owner == auth_pubkey => {}
        Some(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "name not owned by auth key"})),
            )
                .into_response()
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "name not found"})),
            )
                .into_response()
        }
    }
    // One active name per pubkey holds for the target too.
    if let Some(existing) = app.name_of(&new_pubkey) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "new pubkey already has a name", "name": existing})),
        )
            .into_response();
    }

    // Atomic swap guarded by current ownership; the partial-unique pubkey
    // index catches a concurrent registration by the new key → 409.
    let res = app.db.lock().execute(
        "UPDATE names SET pubkey = ?3 WHERE name = ?1 AND pubkey = ?2 AND released_at IS NULL",
        rusqlite::params![name, auth_pubkey, new_pubkey],
    );
    match res {
        // 0 rows: ownership changed or name released concurrently.
        Ok(0) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "transfer conflict"})),
        )
            .into_response(),
        Ok(_) => {
            // The picture belonged to the old key's owner; never inherit it.
            app.purge_avatar(&name);
            tracing::info!("transferred {name}: {auth_pubkey} -> {new_pubkey}");
            (
                StatusCode::OK,
                Json(json!({
                    "name": name,
                    "transferred": true,
                    "nip05": format!("{name}@{DOMAIN}"),
                    "pubkey": new_pubkey,
                })),
            )
                .into_response()
        }
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "new pubkey already has a name"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("db transfer failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "db error"})),
            )
                .into_response()
        }
    }
}

async fn unregister(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow("unreg", &ip, 10, Duration::from_secs(3600)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    let path = format!("/api/v1/register/{name}");
    let (auth_pubkey, auth_id) = match verify_nip98(&headers, &Method::DELETE, &path, &[]) {
        Ok(v) => v,
        Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
    };
    if !app.auth_event_fresh(&auth_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth event replayed"})),
        )
            .into_response();
    }
    if app.cooldown_active("namechange", &auth_pubkey, NAME_CHANGE_COOLDOWN) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "name_change_cooldown"})),
        )
            .into_response();
    }
    match app.lookup(&name) {
        Some(owner) if owner == auth_pubkey => {
            let res = app.db.lock().execute(
                "UPDATE names SET released_at = ?2 WHERE name = ?1 AND released_at IS NULL",
                rusqlite::params![name, unix_now()],
            );
            match res {
                Ok(_) => {
                    app.record_op("namechange", &auth_pubkey);
                    app.purge_avatar(&name);
                    tracing::info!("released {name}");
                    (
                        StatusCode::OK,
                        Json(json!({"name": name, "released": true})),
                    )
                        .into_response()
                }
                Err(e) => {
                    tracing::error!("db release failed: {e}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "db error"})),
                    )
                        .into_response()
                }
            }
        }
        Some(_) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "not the owner"})),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "name not found"})),
        )
            .into_response(),
    }
}

/// Strict avatar filename shape: 64 lowercase hex chars + ".png". Nothing
/// else ever touches the filesystem (kills traversal by construction).
fn valid_avatar_file(file: &str) -> bool {
    file.len() == 68
        && file.ends_with(".png")
        && file[..64]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// POST /api/v1/avatar/{name} — set the avatar for an owned, active name.
/// Raw image body; NIP-98 signed by the owner (payload hash makes the
/// upload replay-proof). Limited to AVATAR_CHANGES_PER_DAY per rolling 24h.
async fn avatar_upload(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow("avatar", &ip, 10, Duration::from_secs(3600)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid name"})),
        )
            .into_response();
    }
    let path = format!("/api/v1/avatar/{name}");
    let (auth_pubkey, auth_id) = match verify_nip98(&headers, &Method::POST, &path, &body) {
        Ok(v) => v,
        Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
    };
    if !app.auth_event_fresh(&auth_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth event replayed"})),
        )
            .into_response();
    }
    // Cheap ownership pre-check before burning CPU on image work; the
    // authoritative check happens transactionally with the upsert below.
    match app.lookup(&name) {
        Some(owner) if owner == auth_pubkey => {}
        Some(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "not the owner"})),
            )
                .into_response()
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "name not found"})),
            )
                .into_response()
        }
    }

    // Decode/resize is CPU-heavy and runs on attacker-controlled input — push
    // it to the blocking pool so a large image can't stall the async runtime
    // (which also serves the unauthenticated read endpoints).
    let png = match tokio::task::spawn_blocking(move || avatar::process(&body)).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": e}))).into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "processing error"})),
            )
                .into_response()
        }
    };
    let hash = hex::encode(Sha256::digest(&png));

    let now = unix_now();
    {
        let mut guard = app.db.lock();
        let tx = match guard.transaction() {
            Ok(t) => t,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "db error"})),
                )
                    .into_response()
            }
        };
        // Daily cap inside the same transaction as the insert, so
        // concurrent uploads can't slip past it.
        let changes: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM avatar_changes WHERE name = ?1 AND changed_at > ?2",
                rusqlite::params![name, now - 86_400],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if changes >= AVATAR_CHANGES_PER_DAY {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "avatar_rate_limited"})),
            )
                .into_response();
        }
        let old_hash: Option<String> = tx
            .query_row("SELECT hash FROM avatars WHERE name = ?1", [&name], |r| {
                r.get(0)
            })
            .ok();
        // Ownership re-checked atomically: a release or transfer racing
        // this upload leaves zero rows touched.
        let n = tx.execute(
            "INSERT INTO avatars (name, hash, updated_at)
             SELECT ?1, ?2, ?3 WHERE EXISTS(
                SELECT 1 FROM names
                WHERE name = ?1 AND pubkey = ?4 AND released_at IS NULL)
             ON CONFLICT(name) DO UPDATE SET
                hash = excluded.hash, updated_at = excluded.updated_at",
            rusqlite::params![name, hash, now, auth_pubkey],
        );
        match n {
            Ok(0) => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "ownership changed"})),
                )
                    .into_response()
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!("avatar upsert failed: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "db error"})),
                )
                    .into_response();
            }
        }
        let _ = tx.execute(
            "INSERT INTO avatar_changes (name, changed_at) VALUES (?1, ?2)",
            rusqlite::params![name, now],
        );
        let _ = tx.execute(
            "DELETE FROM avatar_changes WHERE changed_at < ?1",
            [now - 2 * 86_400],
        );
        // Refcounted unlink of the replaced file (content-hash dedup means
        // another name may still reference it).
        let mut unlink: Option<String> = None;
        if let Some(old) = &old_hash {
            if *old != hash {
                let still: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM avatars WHERE hash = ?1",
                        [old],
                        |r| r.get(0),
                    )
                    .unwrap_or(1);
                if still == 0 {
                    unlink = Some(old.clone());
                }
            }
        }
        // Write the image only now that the upload is authorized and about to
        // be recorded. A rejected upload (rate limit or ownership) returns
        // before reaching here, so it never touches disk — no orphan to clean
        // up. The file still lands before the row commits, so a reader that
        // sees the row always finds the file.
        let final_path = app.avatar_dir.join(format!("{hash}.png"));
        if !final_path.exists() {
            let tmp = app.avatar_dir.join(format!("{hash}.png.tmp"));
            if std::fs::write(&tmp, &png).is_err() || std::fs::rename(&tmp, &final_path).is_err() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "storage error"})),
                )
                    .into_response();
            }
        }
        if tx.commit().is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "db error"})),
            )
                .into_response();
        }
        if let Some(old) = unlink {
            let _ = std::fs::remove_file(app.avatar_dir.join(format!("{old}.png")));
        }
    }
    tracing::info!("avatar set for {name}");
    (
        StatusCode::CREATED,
        Json(json!({"name": name, "avatar": hash})),
    )
        .into_response()
}

/// DELETE /api/v1/avatar/{name} — remove an owned name's avatar.
async fn avatar_delete(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow("avatar", &ip, 10, Duration::from_secs(3600)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid name"})),
        )
            .into_response();
    }
    let path = format!("/api/v1/avatar/{name}");
    let (auth_pubkey, auth_id) = match verify_nip98(&headers, &Method::DELETE, &path, &[]) {
        Ok(v) => v,
        Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
    };
    if !app.auth_event_fresh(&auth_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth event replayed"})),
        )
            .into_response();
    }
    match app.lookup(&name) {
        Some(owner) if owner == auth_pubkey => {
            app.purge_avatar(&name);
            (
                StatusCode::OK,
                Json(json!({"name": name, "deleted": true})),
            )
                .into_response()
        }
        Some(_) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "not the owner"})),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "name not found"})),
        )
            .into_response(),
    }
}

/// GET /api/v1/avatar/{hash}.png — serve a processed avatar. Content is
/// immutable (content-addressed), so far-future caching is safe.
async fn avatar_get(
    State(app): State<Arc<App>>,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !app.allow("read", &client_ip(&headers), 120, Duration::from_secs(60)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    if !valid_avatar_file(&file) {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }
    match std::fs::read(app.avatar_dir.join(&file)) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "image/png"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (header::CONTENT_SECURITY_POLICY, "default-src 'none'"),
                (
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable",
                ),
                (
                    header::CONTENT_DISPOSITION,
                    "inline; filename=\"avatar.png\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

/// GET /api/v1/profile/{name} — public profile: pubkey + avatar hash. The
/// client uses the hash as its cache key (responses are not cacheable).
async fn profile(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !app.allow("read", &client_ip(&headers), 120, Duration::from_secs(60)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name) {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }
    match app.lookup(&name) {
        Some(pubkey) => {
            let avatar = app.avatar_hash(&name);
            (
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                json!({"name": name, "pubkey": pubkey, "avatar": avatar}).to_string(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn landing() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>goblin — money that keeps quiet</title>
<style>
body{margin:0;background:#0E0E0C;color:#FAFAF7;font:16px/1.5 system-ui,sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center}
main{max-width:520px;padding:32px}
h1{font-size:44px;letter-spacing:-1.5px;margin:0 0 12px;color:#FFD60A}
p{color:#9A988F;margin:8px 0}
code{background:#1A1A17;border-radius:6px;padding:2px 6px;color:#FAFAF7}
</style></head><body><main>
<h1>goblin</h1>
<p>Money that keeps quiet.</p>
<p>A peer-to-peer wallet for grin. Payments travel as end-to-end encrypted
nostr messages. Usernames here look like <code>you@goblin.st</code>.</p>
<p>Relay: <code>wss://nrelay.us-ea.st</code></p>
</main></body></html>"#,
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let db_path =
        std::env::var("NIP05_DB").unwrap_or_else(|_| "/opt/goblin/nip05d/nip05.db".to_string());
    let avatar_dir = std::env::var("AVATAR_DIR")
        .unwrap_or_else(|_| "/opt/goblin/nip05d/avatars".to_string());
    let app = Arc::new(App::open(&db_path, PathBuf::from(&avatar_dir)));

    let router = Router::new()
        .route("/.well-known/nostr.json", get(well_known))
        .route("/api/v1/name/{name}", get(availability))
        .route("/api/v1/register", axum::routing::post(register))
        .route("/api/v1/register/{name}", axum::routing::delete(unregister))
        .route("/api/v1/transfer", axum::routing::post(transfer))
        .route("/api/v1/profile/{name}", get(profile))
        .route(
            "/api/v1/avatar/{key}",
            axum::routing::post(avatar_upload)
                .delete(avatar_delete)
                .get(avatar_get)
                .layer(DefaultBodyLimit::max(avatar::MAX_RAW_BYTES)),
        )
        .route("/api/v1/health", get(health))
        .route("/", get(landing))
        .with_state(app);

    let bind = std::env::var("NIP05_BIND").unwrap_or_else(|_| BIND_ADDR.to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    tracing::info!("goblin-nip05d listening on {bind}, db={db_path}, avatars={avatar_dir}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(valid_name("ada"));
        assert!(valid_name("ada.wren-99_x"));
        assert!(!valid_name("ab"));
        assert!(!valid_name("Ada"));
        assert!(!valid_name(".ada"));
        assert!(!valid_name("ada."));
        assert!(!valid_name("a d a"));
        assert!(!valid_name(&"a".repeat(31)));
        assert!(valid_name(&"a".repeat(30)));
        assert!(!valid_name("päge"));
    }

    /// The transfer UPDATE's invariants at the SQL layer: owner-guarded swap,
    /// no-op on wrong owner, and the partial-unique pubkey index rejecting a
    /// target key that already holds an active name.
    #[test]
    fn transfer_sql_invariants() {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(
            "CREATE TABLE names (
                name TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                released_at INTEGER
            );
            CREATE UNIQUE INDEX idx_active_pubkey
                ON names(pubkey) WHERE released_at IS NULL;",
        )
        .unwrap();
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        db.execute(
            "INSERT INTO names (name, pubkey, created_at) VALUES ('alice', ?1, 1)",
            rusqlite::params![a],
        )
        .unwrap();

        let xfer = "UPDATE names SET pubkey = ?3 \
                    WHERE name = ?1 AND pubkey = ?2 AND released_at IS NULL";

        // Wrong owner: guarded update touches nothing.
        let n = db
            .execute(xfer, rusqlite::params!["alice", b, c])
            .unwrap();
        assert_eq!(n, 0);

        // Owner swap succeeds and the mapping moves.
        let n = db
            .execute(xfer, rusqlite::params!["alice", a, b])
            .unwrap();
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
        // And the mapping is unchanged after the failed transfer.
        let owner: String = db
            .query_row("SELECT pubkey FROM names WHERE name='alice'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(owner, b);
    }

    #[test]
    fn avatar_file_validation() {
        let good = format!("{}.png", "a1".repeat(32));
        assert!(valid_avatar_file(&good));
        assert!(!valid_avatar_file("../../etc/passwd"));
        assert!(!valid_avatar_file("..%2f..%2fetc%2fpasswd"));
        assert!(!valid_avatar_file(&format!("{}.png", "A1".repeat(32))));
        assert!(!valid_avatar_file(&format!("{}.png", "a1".repeat(16))));
        assert!(!valid_avatar_file(&format!("{}.jpg", "a1".repeat(32))));
        assert!(!valid_avatar_file(&"a".repeat(68)));
        assert!(!valid_avatar_file(""));
    }

    fn avatar_test_db() -> Connection {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(
            "CREATE TABLE names (
                name TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                released_at INTEGER
            );
            CREATE UNIQUE INDEX idx_active_pubkey
                ON names(pubkey) WHERE released_at IS NULL;
            CREATE TABLE avatars (
                name TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE avatar_changes (
                name TEXT NOT NULL,
                changed_at INTEGER NOT NULL
            );",
        )
        .unwrap();
        db
    }

    /// The ownership-gated avatar upsert: writes for the active owner,
    /// touches nothing once the name is released or owned by another key.
    #[test]
    fn avatar_upsert_requires_active_ownership() {
        let db = avatar_test_db();
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

        // Owner writes.
        let n = db
            .execute(upsert, rusqlite::params!["alice", "h1", 1, a])
            .unwrap();
        assert_eq!(n, 1);
        // Non-owner is a no-op.
        let n = db
            .execute(upsert, rusqlite::params!["alice", "h2", 2, b])
            .unwrap();
        assert_eq!(n, 0);
        // Owner update replaces the hash.
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
        // Released name: gate closes.
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
        let db = avatar_test_db();
        db.execute_batch(
            "INSERT INTO avatars VALUES ('alice', 'same', 1);
             INSERT INTO avatars VALUES ('bob', 'same', 1);",
        )
        .unwrap();
        db.execute("DELETE FROM avatars WHERE name='alice'", [])
            .unwrap();
        let still: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM avatars WHERE hash='same'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(still, 1, "shared hash must survive one name's deletion");
    }

    /// The rolling-24h change counter: 5 changes pass, the 6th is denied.
    #[test]
    fn avatar_daily_window() {
        let db = avatar_test_db();
        let now = 1_000_000i64;
        for i in 0..AVATAR_CHANGES_PER_DAY {
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
        assert!(count >= AVATAR_CHANGES_PER_DAY, "6th change must be denied");
        // Entries older than the window stop counting.
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM avatar_changes WHERE name='alice' AND changed_at > ?1",
                [now + 90_000 - 86_400],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    /// Quarantine removed: a released name is immediately revivable by a
    /// new key via the register upsert.
    #[test]
    fn released_name_immediately_reclaimable() {
        let db = avatar_test_db();
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

    #[test]
    fn pubkey_validation() {
        assert!(valid_pubkey_hex(
            "91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05"
        ));
        assert!(!valid_pubkey_hex(
            "91CF9DBBEA5E6511FD2BBB190B112055EE4131C5D2BBB9FAEDF3EE8CBEAC0D05"
        ));
        assert!(!valid_pubkey_hex("abc"));
    }
}
