use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use dashmap::DashMap;

use serde_json::json;
use once_cell::sync::Lazy;
use crate::AppState;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub plan: String,
    pub rate_limit: i32,
    pub deployment_id: String,
}

// In-memory rate limiting store
static RATE_LIMITS: Lazy<DashMap<String, (u32, DateTime<Utc>)>> = Lazy::new(DashMap::new);

pub async fn validate_license_jwt(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Check if FIPS mode is enabled - if not, skip authentication
    if !state.config.fips_mode {
        tracing::info!("FIPS mode disabled - skipping authentication");
        return Ok(next.run(request).await);
    }

    // 1. Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "missing_authorization",
                    "message": "Missing or invalid Authorization header (required in FIPS mode)"
                }))
            )
        })?;

    // 2. Decode and validate JWT token using HMAC secret
    let decoding_key = DecodingKey::from_secret(&state.license_jwt_secret[..]);
    
    // Use FIPS-compliant algorithm when FIPS mode is enabled
    let algorithm = if state.config.fips_mode {
        Algorithm::HS256 // FIPS-approved HMAC-SHA256
    } else {
        Algorithm::HS256 // Default to HS256 for consistency
    };
    
    let validation = Validation::new(algorithm);

    let token_data = decode::<Claims>(auth_header, &decoding_key, &validation)
        .map_err(|e| {
            eprintln!("JWT decode error: {:?}", e);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_token",
                    "message": "Invalid or expired token"
                }))
            )
        })?;

    // 3. Check rate limiting
    let claims = token_data.claims;
    let key = format!("{}:{}", claims.sub, claims.deployment_id);
    
    let now = Utc::now();
    let entry = RATE_LIMITS
        .entry(key.clone())
        .and_modify(|entry| {
            let (count, start) = *entry;
            if now.signed_duration_since(start).num_seconds() >= 3600 {
                // Reset window
                *entry = (1, now);
            } else {
                *entry = (count + 1, start);
            }
        })
        .or_insert((1, now));
    
    let (current_count, _window_start) = *entry;

    if current_count > claims.rate_limit as u32 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limit_exceeded",
                "message": format!("Rate limit exceeded. Limit: {}, Used: {}", claims.rate_limit, current_count)
            }))
        ));
    }

    // 4. Continue with the request
    Ok(next.run(request).await)
}
