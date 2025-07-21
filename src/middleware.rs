use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{Response, IntoResponse},
    body::Body,
    Json,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde_json::json;
use once_cell::sync::Lazy;
use dashmap::DashMap;

use crate::AppState;

/// Record representing a row from the `api_keys` table
/// Only the fields we need for runtime checks are selected.
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub plan: String,
    pub rate_limit_per_minute: Option<i32>,
    pub is_active: Option<bool>,
}

/// Middleware that extracts an `X-API-KEY` (or bearer/query) credential, checks it
/// against Supabase/Postgres, enforces quotas, and stores the `ApiKeyRecord` in
/// request extensions for downstream handlers.
pub async fn validate_api_key(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // ------------------------------------------------------------
    // 1. Extract API key from header / bearer / query parameter
    // ------------------------------------------------------------
    let Some(raw_key) = extract_api_key(&req) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "missing api key"}))).into_response();
    };

    // ------------------------------------------------------------
    // 2. Lookup key in database
    // ------------------------------------------------------------
    let key_record = sqlx::query_as::<_, ApiKeyRecord>(
        r#"SELECT id, plan, rate_limit_per_minute, is_active FROM api_keys WHERE api_key = $1"#
    )
    .bind(raw_key)
    .persistent(false) // avoid cached plan mismatch if column list changes
    .fetch_optional(&state.pool.pool)
    .await;

    let key_record = match key_record {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "database error while verifying api key");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "database error"}))).into_response();
        }
    };

    let Some(record) = key_record else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid api key"}))).into_response();
    };

    // ------------------------------------------------------------
    // 3. Validate record (active / not expired / quota)
    // ------------------------------------------------------------
    if record.is_active == Some(false) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "key inactive"}))).into_response();
    }

    // ------------------------------------------------------------
    // Rate limiting based on `rate_limit_per_minute`
    // ------------------------------------------------------------
    if let Some(limit) = record.rate_limit_per_minute {
        let now = Utc::now();
        let mut entry = RATE_LIMIT_MAP
            .entry(record.id)
            .or_insert((0u32, now));
        let (ref mut count, ref mut ts) = *entry;
        if now.signed_duration_since(*ts).num_seconds() >= 60 {
            *count = 0;
            *ts = now;
        }
        if *count >= limit as u32 {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "rate limit exceeded"}))).into_response();
        }
        *count += 1;
    }

    // TODO: Rate-limit per minute if `rate_limit_per_minute` is set.

    // ------------------------------------------------------------
    // 4. Attach record to request extensions so handlers can access it
    // ------------------------------------------------------------
    req.extensions_mut().insert(record.clone());

    // ------------------------------------------------------------
    // 5. Call downstream handler
    // ------------------------------------------------------------
    let response = next.run(req).await;



    response
}

static RATE_LIMIT_MAP: Lazy<DashMap<Uuid, (u32, DateTime<Utc>)>> = Lazy::new(|| DashMap::new());

// ------------------------------------------------------------
// Helper — extract API key from headers or query string
// ------------------------------------------------------------
pub fn extract_api_key(req: &Request<Body>) -> Option<String> {
    // 1. Custom header
    if let Some(value) = req.headers().get("x-api-key") {
        if let Ok(v) = value.to_str() {
            return Some(v.to_owned());
        }
    }

    // 2. Authorization: Bearer <key>
    if let Some(value) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(v) = value.to_str() {
            if let Some(stripped) = v.strip_prefix("Bearer ") {
                return Some(stripped.to_owned());
            }
        }
    }

    // 3. Query parameter ?api_key=<key>
    if let Some(query) = req.uri().query() {
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if k == "api_key" {
                return Some(v.into_owned());
            }
        }
    }

    None
} 