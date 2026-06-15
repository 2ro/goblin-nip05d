// HTTP surface for avatars: upload, delete, and serving. The image processing
// itself lives in `crate::avatar`.

use crate::auth::verify_nip98;
use crate::avatar;
use crate::db::App;
use crate::names::{valid_avatar_file, valid_name};
use crate::util::{client_ip, unix_now};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// POST /api/v1/avatar/{name} — set the avatar for an owned, active name.
/// Raw image body; NIP-98 signed by the owner (payload hash makes the
/// upload replay-proof). Limited to `avatar_changes_per_day` per rolling 24h.
pub async fn avatar_upload(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow_write("avatar", &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name, app.cfg.name_min, app.cfg.name_max) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid name"})),
        )
            .into_response();
    }
    let path = format!("/api/v1/avatar/{name}");
    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::POST,
        &path,
        &body,
        &app.cfg.base_url,
        app.cfg.auth_max_age_secs,
    ) {
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
        if changes >= app.cfg.avatar_changes_per_day {
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
                    .query_row("SELECT COUNT(*) FROM avatars WHERE hash = ?1", [old], |r| {
                        r.get(0)
                    })
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
pub async fn avatar_delete(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow_write("avatar", &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name, app.cfg.name_min, app.cfg.name_max) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid name"})),
        )
            .into_response();
    }
    let path = format!("/api/v1/avatar/{name}");
    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::DELETE,
        &path,
        &[],
        &app.cfg.base_url,
        app.cfg.auth_max_age_secs,
    ) {
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
            (StatusCode::OK, Json(json!({"name": name, "deleted": true}))).into_response()
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
pub async fn avatar_get(
    State(app): State<Arc<App>>,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !app.allow_read(&client_ip(&headers)) {
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
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
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
