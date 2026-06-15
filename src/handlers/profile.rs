// Public profile lookup: `/api/v1/profile/{name}`.

use crate::db::App;
use crate::names::valid_name;
use crate::util::client_ip;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

/// GET /api/v1/profile/{name} — public profile: the active pubkey for a name.
/// Avatars are not served here; clients render them from the pubkey.
pub async fn profile(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !app.allow_read(&client_ip(&headers)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name, app.cfg.name_min, app.cfg.name_max) {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }
    match app.lookup(&name) {
        Some(pubkey) => (
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            json!({"name": name, "pubkey": pubkey}).to_string(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}
