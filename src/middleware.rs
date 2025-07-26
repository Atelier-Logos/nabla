use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    body::Body,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize};
use uuid::Uuid;
use serde_json::json;
use once_cell::sync::Lazy;
use serde::Serialize;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub plan: String,
    pub rate_limit: u32,
    pub deployment_id: Option<Uuid>,
}

static RATE_LIMIT_MAP: Lazy<DashMap<String, (u32, DateTime<Utc>)>> = Lazy::new(|| DashMap::new());

pub async fn validate_license_jwt(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    // 1. Extract token from header or query string
    let token = match extract_api_key(&req) {
        Some(t) => t,
        None => {
            return Ok((StatusCode::TOO_MANY_REQUESTS, json_error("rate limit exceeded")).into_response());
        }
    };

    // 2. Decode and validate JWT token using HMAC secret
    let decoding_key = DecodingKey::from_secret(&state.license_jwt_secret[..]);
    let validation = Validation::new(Algorithm::HS256);

    let token_data = decode::<Claims>(&token, &decoding_key, &validation)
    .map_err(|e| {
        eprintln!("JWT decode error: {:?}", e);
        (StatusCode::UNAUTHORIZED, json_error("invalid or expired license token"))
    })?; 

    let claims = token_data.claims;

    // 3. Rate limiting per minute from claims.rate_limit
    let now = Utc::now();
    let mut entry = RATE_LIMIT_MAP
        .entry(claims.jti.clone())
        .or_insert((0u32, now));
    let (ref mut count, ref mut ts) = *entry;
    if now.signed_duration_since(*ts).num_seconds() >= 60 {
        *count = 0;
        *ts = now;
    }
    if *count >= claims.rate_limit {
        return Ok((StatusCode::TOO_MANY_REQUESTS, json_error("rate limit exceeded")).into_response());
    }
    *count += 1;

    // 4. Attach claims to request extensions for downstream handlers
    req.extensions_mut().insert(claims);

    // 5. Call next handler
    Ok(next.run(req).await)
}

fn json_error(msg: &str) -> axum::Json<serde_json::Value> {
    axum::Json(json!({ "error": msg }))
}

// Extract token from `x-api-key`, `Authorization: Bearer`, or `?api_key=`
fn extract_api_key(req: &Request<Body>) -> Option<String> {
    // x-api-key header
    if let Some(value) = req.headers().get("x-api-key") {
        if let Ok(v) = value.to_str() {
            return Some(v.to_owned());
        }
    }

    // Authorization: Bearer
    if let Some(value) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(v) = value.to_str() {
            if let Some(stripped) = v.strip_prefix("Bearer ") {
                return Some(stripped.to_owned());
            }
        }
    }

    // Query param ?api_key=
    if let Some(query) = req.uri().query() {
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if k == "api_key" {
                return Some(v.into_owned());
            }
        }
    }
    None
}
