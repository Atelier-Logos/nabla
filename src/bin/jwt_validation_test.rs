use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, errors::ErrorKind};
use nabla_cli::config::Config;
use serde::Deserialize;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Validate JWT tokens
#[derive(Parser, Debug)]
#[command(name = "jwt_validation_test")]
#[command(about = "Validate JWT tokens")]
#[command(version = VERSION)]
struct Args {
    /// JWT token to validate
    #[arg(long)]
    token: String,

    /// Base64-encoded secret key (if not provided, uses default test key)
    #[arg(long)]
    secret: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PlanFeatures {
    chat_enabled: bool,
    api_access: bool,
    file_upload_limit_mb: u32,
    concurrent_requests: u32,
    custom_models: bool,
    sbom_generation: bool,
    vulnerability_scanning: bool,
    signed_attestation: bool,
    monthly_binaries: u32,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let secret_base64 = args.secret.unwrap_or_else(|| {
        // Use config system to get consistent key
        Config::from_env()
            .expect("Failed to load config")
            .license_signing_key
    });

    let decoded = URL_SAFE_NO_PAD
        .decode(&secret_base64)
        .map_err(|_| anyhow::anyhow!("Base64 decoding failed"))?;

    let decoding_key = DecodingKey::from_secret(&decoded);
    let validation = Validation::new(Algorithm::HS256);

    match decode::<Claims>(&args.token, &decoding_key, &validation) {
        Ok(token_data) => {
            println!("✅ Token is valid!");
            println!("{:#?}", token_data.claims);
        }
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => {
                println!("❌ Token is invalid");
                std::process::exit(1);
            }
            ErrorKind::InvalidSignature => {
                println!("❌ Invalid signature");
                std::process::exit(1);
            }
            ErrorKind::ExpiredSignature => {
                println!("⌛ Token expired");
                std::process::exit(1);
            }
            _ => {
                println!("Other error: {:?}", err);
                std::process::exit(1);
            }
        },
    }

    Ok(())
}
