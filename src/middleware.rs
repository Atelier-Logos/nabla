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

use crate::AppState;

/// Record representing a row from the `api_keys` table
/// Only the fields we need for runtime checks are selected.
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub tier: String,
    pub rate_limit_per_minute: Option<i32>,
    pub monthly_quota: Option<i32>,
    pub current_usage: Option<i32>,
    pub is_active: Option<bool>,
    pub expires_at: Option<DateTime<Utc>>,
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
    let key_record = sqlx::query_as!(
        ApiKeyRecord,
        r#"SELECT id, tier, rate_limit_per_minute, monthly_quota, current_usage,
                  is_active, expires_at
           FROM api_keys
           WHERE api_key = $1"#,
        raw_key
    )
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

    if let Some(exp) = record.expires_at {
        if exp < Utc::now() {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "key expired"}))).into_response();
        }
    }

    if let (Some(quota), Some(usage)) = (record.monthly_quota, record.current_usage) {
        if usage >= quota {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "quota exceeded"}))).into_response();
        }
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

    // ------------------------------------------------------------
    // 6. On successful response, increment usage counter
    // ------------------------------------------------------------
    if response.status().is_success() {
        // Ignore errors – they are logged and do not affect the response.
        if let Err(e) = sqlx::query!(
            "UPDATE api_keys SET current_usage = current_usage + 1 WHERE id = $1",
            record.id
        )
        .execute(&state.pool.pool)
        .await
        {
            tracing::error!(error = %e, "failed to increment current_usage for api key");
        }
    }

    response
}

// ------------------------------------------------------------
// Helper — extract API key from headers or query string
// ------------------------------------------------------------
fn extract_api_key(req: &Request<Body>) -> Option<String> {
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