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
    pub sub: String,        // Company name (e.g., "acme-corp")
    pub uid: String,        // User ID within the company
    pub exp: i64,           // Expiration timestamp
    pub iat: i64,           // Issued at timestamp
    pub jti: String,        // JWT ID
    pub rate_limit: i32,    // Requests per hour
    pub deployment_id: String, // UUID for deployment isolation
    pub features: PlanFeatures, // Feature flags - required field
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlanFeatures {
    pub chat_enabled: bool,
    pub api_access: bool,
    pub file_upload_limit_mb: u32,
    pub concurrent_requests: u32,
    pub custom_models: bool,
    pub sbom_generation: bool,
    pub vulnerability_scanning: bool,
    pub binary_attestation: bool,
    pub monthly_binaries: u32,
}


// In-memory rate limiting store
static RATE_LIMITS: Lazy<DashMap<String, (u32, DateTime<Utc>)>> = Lazy::new(DashMap::new);

impl PlanFeatures {
    pub fn default_oss() -> Self {
        Self {
            chat_enabled: false,
            api_access: true,
            file_upload_limit_mb: 10,
            concurrent_requests: 1,
            custom_models: false,
            sbom_generation: true,
            vulnerability_scanning: true,
            binary_attestation: false,
            monthly_binaries: 100,
        }
    }
}

pub async fn validate_license_jwt(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Check if FIPS mode is enabled
    if !state.config.fips_mode {
        tracing::info!("FIPS mode disabled - using default OSS features");
        // Add default OSS features to request extensions for endpoints to use
        request.extensions_mut().insert(PlanFeatures::default_oss());
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

    // 4. Add features to request extensions for endpoints to use
    request.extensions_mut().insert(claims.features.clone());
    
    // 5. Continue with the request
    Ok(next.run(request).await)
}
