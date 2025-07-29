use clap::Parser;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, errors::ErrorKind};
use serde::Deserialize;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

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
    exp: usize,
    iat: usize,
    jti: String,
    plan: String,
    rate_limit: u32,
    deployment_id: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    let secret_base64 = args.secret.unwrap_or_else(|| {
        "ZwXQPW2lbCC74DYLgjFwnHaqsakReigw4Jvu5CHeRoU".to_string()
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
        },
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => {
                println!("❌ Token is invalid");
                std::process::exit(1);
            },
            ErrorKind::InvalidSignature => {
                println!("❌ Invalid signature");
                std::process::exit(1);
            },
            ErrorKind::ExpiredSignature => {
                println!("⌛ Token expired");
                std::process::exit(1);
            },
            _ => {
                println!("Other error: {:?}", err);
                std::process::exit(1);
            },
        },
    }
    
    Ok(())
}
