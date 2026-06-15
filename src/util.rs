// Small cross-cutting helpers.

use axum::http::HeaderMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The client IP, taken from `X-Real-IP`. SECURITY-CRITICAL: the reverse proxy
/// MUST set this header from the real peer address — all per-IP rate limiting
/// keys off it, so a missing/forgeable value defeats the limiter.
pub fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
