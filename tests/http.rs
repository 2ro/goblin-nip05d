// HTTP integration tests: drive the real router via `tower::ServiceExt::oneshot`
// with signed NIP-98 auth events, covering the registration, transfer, release
// and avatar flows including the auth/replay/cooldown edge cases.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use goblin_nip05d::{handlers, App, Config};
use http_body_util::BodyExt;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const BASE_URL: &str = "https://goblin.st";

/// Build a NIP-98 `Authorization: Nostr <b64>` header value, signed by `keys`,
/// for the given method/path/body. `age_secs` ages the event's created_at into
/// the past (negative = post-dated); the default flow uses 0.
fn nip98_header(keys: &Keys, method: &str, path: &str, body: &[u8], age_secs: i64) -> String {
    let url = format!("{BASE_URL}{path}");
    let mut tags = vec![
        Tag::parse(["u", &url]).unwrap(),
        Tag::parse(["method", method]).unwrap(),
    ];
    if !body.is_empty() {
        let payload = hex::encode(Sha256::digest(body));
        tags.push(Tag::parse(["payload", &payload]).unwrap());
    }
    let created = Timestamp::now().as_secs() as i64 - age_secs;
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created as u64))
        .sign_with_keys(keys)
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(event.as_json());
    format!("Nostr {b64}")
}

fn test_app() -> Arc<App> {
    Arc::new(App::open(Config::for_test()))
}

async fn send(app: Arc<App>, req: Request<Body>) -> (StatusCode, Value) {
    let resp = handlers::routes(app).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn register_req(keys: &Keys, name: &str) -> Request<Body> {
    let body = serde_json::json!({ "name": name, "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    let auth = nip98_header(keys, "POST", "/api/v1/register", &body, 0);
    Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.1")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn register_happy_path() {
    let app = test_app();
    let keys = Keys::generate();
    let (status, json) = send(app, register_req(&keys, "alice")).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["nip05"], "alice@goblin.st");
}

#[tokio::test]
async fn register_replay_rejected() {
    let app = test_app();
    let keys = Keys::generate();
    let body = serde_json::json!({ "name": "alice", "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    let auth = nip98_header(&keys, "POST", "/api/v1/register", &body, 0);
    let build = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/register")
            .header("authorization", auth.clone())
            .header("x-real-ip", "10.0.0.2")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap()
    };
    let (s1, _) = send(app.clone(), build()).await;
    assert_eq!(s1, StatusCode::CREATED);
    // Same signed auth event a second time → replay rejection.
    let (s2, json) = send(app, build()).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth event replayed");
}

#[tokio::test]
async fn register_expired_auth_rejected() {
    let app = test_app();
    let keys = Keys::generate();
    let body = serde_json::json!({ "name": "alice", "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    // 120s in the past — older than the 60s max age.
    let auth = nip98_header(&keys, "POST", "/api/v1/register", &body, 120);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.3")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth event expired or post-dated");
}

#[tokio::test]
async fn register_u_tag_mismatch_rejected() {
    let app = test_app();
    let keys = Keys::generate();
    let body = serde_json::json!({ "name": "alice", "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    // Sign for the wrong path so the u-tag won't match.
    let auth = nip98_header(&keys, "POST", "/api/v1/transfer", &body, 0);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.4")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth event url mismatch");
}

#[tokio::test]
async fn register_wrong_pubkey_rejected() {
    let app = test_app();
    let signer = Keys::generate();
    let other = Keys::generate();
    // Body claims `other`'s pubkey but is signed by `signer`.
    let body = serde_json::json!({ "name": "alice", "pubkey": other.public_key().to_hex() })
        .to_string()
        .into_bytes();
    let auth = nip98_header(&signer, "POST", "/api/v1/register", &body, 0);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.5")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth pubkey does not match body pubkey");
}

#[tokio::test]
async fn taken_name_conflicts() {
    let app = test_app();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&alice, "shared")).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, json) = send(app, register_req(&bob, "shared")).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(json["error"], "name taken");
}

#[tokio::test]
async fn second_name_per_key_conflicts() {
    let app = test_app();
    let keys = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&keys, "first")).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, json) = send(app, register_req(&keys, "second")).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(json["error"], "pubkey already has a name");
}

#[tokio::test]
async fn release_arms_cooldown_blocking_reregister() {
    let app = test_app();
    let keys = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&keys, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    // Release the name.
    let del_auth = nip98_header(&keys, "DELETE", "/api/v1/register/alice", &[], 0);
    let del = Request::builder()
        .method("DELETE")
        .uri("/api/v1/register/alice")
        .header("authorization", del_auth)
        .header("x-real-ip", "10.0.0.6")
        .body(Body::empty())
        .unwrap();
    let (sdel, _) = send(app.clone(), del).await;
    assert_eq!(sdel, StatusCode::OK);

    // A fresh registration is now blocked by the cooldown the release armed.
    let (sreg, json) = send(app, register_req(&keys, "bob")).await;
    assert_eq!(sreg, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["error"], "name_change_cooldown");
}

#[tokio::test]
async fn transfer_happy_and_conflict() {
    let app = test_app();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let carol = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&alice, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    // Happy: alice transfers "alice" to bob.
    let xfer = |from: &Keys, name: &str, to: &Keys, ip: &str| -> Request<Body> {
        let body = serde_json::json!({ "name": name, "new_pubkey": to.public_key().to_hex() })
            .to_string()
            .into_bytes();
        let auth = nip98_header(from, "POST", "/api/v1/transfer", &body, 0);
        Request::builder()
            .method("POST")
            .uri("/api/v1/transfer")
            .header("authorization", auth)
            .header("x-real-ip", ip)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    let (sx, json) = send(app.clone(), xfer(&alice, "alice", &bob, "10.0.0.7")).await;
    assert_eq!(sx, StatusCode::OK);
    assert_eq!(json["pubkey"], bob.public_key().to_hex());

    // Give carol her own name so she "already has a name".
    let (sc, _) = send(app.clone(), register_req(&carol, "carol")).await;
    assert_eq!(sc, StatusCode::CREATED);

    // Conflict: bob tries to transfer "alice" to carol, who is already taken.
    let (sx2, json2) = send(app, xfer(&bob, "alice", &carol, "10.0.0.8")).await;
    assert_eq!(sx2, StatusCode::CONFLICT);
    assert_eq!(json2["error"], "new pubkey already has a name");
}

/// Build a tiny valid PNG body for avatar tests. `seed` varies the pixels so
/// repeat uploads carry distinct bodies (and thus distinct NIP-98 auth events,
/// avoiding a same-second replay collision in the test).
fn png_bytes(seed: u8) -> Vec<u8> {
    use image::codecs::png::PngEncoder;
    use image::RgbaImage;
    let img = RgbaImage::from_fn(64, 64, |x, y| image::Rgba([x as u8, y as u8, seed, 255]));
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_with_encoder(PngEncoder::new(&mut out))
        .unwrap();
    out
}

#[tokio::test]
async fn avatar_upload_ownership_and_daily_cap() {
    // Avatars need a real directory; build the app with a temp dir.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test();
    cfg.avatar_dir = dir.path().to_string_lossy().into_owned();
    cfg.avatar_changes_per_day = 2;
    let app = Arc::new(App::open(cfg));

    let owner = Keys::generate();
    let stranger = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&owner, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    let upload = |k: &Keys, ip: &str, seed: u8| -> Request<Body> {
        let body = png_bytes(seed);
        let auth = nip98_header(k, "POST", "/api/v1/avatar/alice", &body, 0);
        Request::builder()
            .method("POST")
            .uri("/api/v1/avatar/alice")
            .header("authorization", auth)
            .header("x-real-ip", ip)
            .body(Body::from(body))
            .unwrap()
    };

    // Stranger cannot set the owner's avatar.
    let (ss, json) = send(app.clone(), upload(&stranger, "10.0.1.1", 1)).await;
    assert_eq!(ss, StatusCode::FORBIDDEN);
    assert_eq!(json["error"], "not the owner");

    // Owner can (cap = 2): two succeed, the third is rate-limited.
    let (a1, _) = send(app.clone(), upload(&owner, "10.0.1.2", 2)).await;
    assert_eq!(a1, StatusCode::CREATED);
    let (a2, _) = send(app.clone(), upload(&owner, "10.0.1.2", 3)).await;
    assert_eq!(a2, StatusCode::CREATED);
    let (a3, json3) = send(app, upload(&owner, "10.0.1.2", 4)).await;
    assert_eq!(a3, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json3["error"], "avatar_rate_limited");
}

#[tokio::test]
async fn wellknown_resolves_registered_name() {
    let app = test_app();
    let keys = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&keys, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/nostr.json?name=alice")
        .header("x-real-ip", "10.0.2.1")
        .body(Body::empty())
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["names"]["alice"], keys.public_key().to_hex());
}
