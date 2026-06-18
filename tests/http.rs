// HTTP integration tests: drive the real router via `tower::ServiceExt::oneshot`
// with signed NIP-98 auth events, covering the registration and release flows
// including the auth/replay/cooldown edge cases.

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
    let auth = nip98_header(&keys, "POST", "/api/v1/profile/alice", &body, 0);
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

#[tokio::test]
async fn by_pubkey_reverse_lookup() {
    let app = test_app();
    let keys = Keys::generate();
    let pk = keys.public_key().to_hex();
    let (s1, _) = send(app.clone(), register_req(&keys, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    // Known key → its active name.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/by-pubkey/{pk}"))
        .header("x-real-ip", "10.0.3.1")
        .body(Body::empty())
        .unwrap();
    let (status, json) = send(app.clone(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["name"], "alice");
    assert_eq!(json["pubkey"], pk);

    // Unknown (but well-formed) key → 404.
    let other = Keys::generate().public_key().to_hex();
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/by-pubkey/{other}"))
        .header("x-real-ip", "10.0.3.2")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(app.clone(), req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Malformed key → 404, not a 500.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/by-pubkey/not-a-key")
        .header("x-real-ip", "10.0.3.3")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
