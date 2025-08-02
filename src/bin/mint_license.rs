use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use clap::{ArgGroup, Parser};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Mint a signed license token using HMAC and env var key
#[derive(Parser, Debug)]
#[command(name = "mint_license")]
#[command(about = "Mint a signed license token using HMAC and env var key")]
#[command(version = VERSION)]
#[command(group(
    ArgGroup::new("expiry")
        .required(true)
        .args(&["trial_14", "trial_30", "quarterly", "annual", "three_year"]),
))]
struct Args {
    /// Subject (usually company or user)
    #[arg(long)]
    sub: String,

    /// User ID within the company
    #[arg(long)]
    uid: String,

    /// Deployment ID to tie the token to
    #[arg(long)]
    deployment_id: Option<Uuid>,

    /// Rate limit per hour
    #[arg(long, default_value_t = 60)]
    rate_limit: i32,

    // Feature flags
    /// Enable chat functionality
    #[arg(long)]
    chat_enabled: bool,

    /// Enable API access
    #[arg(long, default_value_t = true)]
    api_access: bool,

    /// File upload limit in MB
    #[arg(long, default_value_t = 10)]
    file_upload_limit_mb: u32,

    /// Concurrent requests limit
    #[arg(long, default_value_t = 1)]
    concurrent_requests: u32,

    /// Enable custom models
    #[arg(long)]
    custom_models: bool,

    /// Enable SBOM generation
    #[arg(long, default_value_t = true)]
    sbom_generation: bool,

    /// Enable vulnerability scanning
    #[arg(long, default_value_t = true)]
    vulnerability_scanning: bool,

    /// Enable signed attestation
    #[arg(long)]
    signed_attestation: bool,

    /// Enable exploitability analysis
    #[arg(long)]
    exploitability_analysis: bool,

    /// Monthly binary analysis limit
    #[arg(long, default_value_t = 100)]
    monthly_binaries: u32,

    /// Set a 14-day trial expiration
    #[arg(long)]
    trial_14: bool,

    /// Set a 30-day trial expiration
    #[arg(long)]
    trial_30: bool,

    /// Set a 3-month (quarterly) expiration
    #[arg(long)]
    quarterly: bool,

    /// Set a 12-month (annual) expiration
    #[arg(long)]
    annual: bool,

    /// Set a 3-year expiration
    #[arg(long)]
    three_year: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    uid: String,
    exp: usize,
    iat: usize,
    jti: String,
    rate_limit: i32,
    deployment_id: String,
    features: PlanFeatures,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlanFeatures {
    chat_enabled: bool,
    api_access: bool,
    file_upload_limit_mb: u32,
    concurrent_requests: u32,
    custom_models: bool,
    sbom_generation: bool,
    vulnerability_scanning: bool,
    exploitability_analysis: bool,
    signed_attestation: bool,
    monthly_binaries: u32,
}

fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok(); // Load from .env if present

    let args = Args::parse();

    // Read secret key from env var, base64 decode it
    let key_b64 = env::var("LICENSE_SIGNING_KEY")
        .map_err(|_| anyhow::anyhow!("Missing LICENSE_SIGNING_KEY env variable"))?;

    let key_bytes = general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim())?;

    // Choose expiration based on flags
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now
        + if args.trial_14 {
            Duration::days(14)
        } else if args.trial_30 {
            Duration::days(30)
        } else if args.quarterly {
            Duration::days(90)
        } else if args.annual {
            Duration::days(365)
        } else {
            Duration::days(365 * 3)
        })
    .timestamp() as usize;

    let features = PlanFeatures {
        chat_enabled: args.chat_enabled,
        api_access: args.api_access,
        file_upload_limit_mb: args.file_upload_limit_mb,
        concurrent_requests: args.concurrent_requests,
        custom_models: args.custom_models,
        sbom_generation: args.sbom_generation,
        vulnerability_scanning: args.vulnerability_scanning,
        exploitability_analysis: args.exploitability_analysis,
        signed_attestation: args.signed_attestation,
        monthly_binaries: args.monthly_binaries,
    };

    let claims = Claims {
        sub: args.sub,
        uid: args.uid,
        exp,
        iat,
        jti: Uuid::new_v4().to_string(),
        rate_limit: args.rate_limit,
        deployment_id: args
            .deployment_id
            .unwrap_or_else(|| Uuid::new_v4())
            .to_string(),
        features,
    };

    // Create encoding key from raw bytes for HMAC (HS256)
    let encoding_key = EncodingKey::from_secret(&key_bytes);

    let token = encode(
        &Header {
            alg: Algorithm::HS256, // Use HMAC-SHA256
            ..Default::default()
        },
        &claims,
        &encoding_key,
    )?;

    println!("{token}");
    Ok(())
}
