use axum::extract::DefaultBodyLimit;
use axum::{
    Router,
    http::{Method, header},
    routing::post,
};
use base64::Engine;
use dotenvy::dotenv;
use reqwest::Client; // Add import for Client
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod binary;
mod cli;
mod config;
mod middleware;
mod routes;
mod ssrf_protection;
// mod providers; // Using enterprise providers instead
mod enterprise;

// Re-export server module so CLI can access it
pub mod server {
    pub use crate::run_server;
}

use config::Config;
use middleware::validate_license_jwt;

// src/main.rs - update AppState
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub client: Client,
    pub base_url: String,
    pub enterprise_features: bool, // Add this field to track enterprise features
    pub license_jwt_secret: Arc<[u8; 32]>,
}

pub async fn run_server(port: u16) -> anyhow::Result<()> {
    // Load environment variables from .env if available
    dotenv().ok();

    // Load config to check deployment type
    let config = Config::from_env()?;

    // Use consistent key loading from config
    let key_b64 = config.license_signing_key.clone();

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim())?;
    // Ensure length is exactly 32, then convert Vec<u8> to [u8; 32]
    let secret_array: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("LICENSE_SIGNING_KEY must be exactly 32 bytes"))?;

    // Wrap fixed-size array in Arc
    let license_jwt_secret = Arc::new(secret_array);
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            "nabla=debug,tower_http=debug",
        ))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    // Load configuration
    let config = Config::from_env()?;

    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // Create HTTP client
    let client = reqwest::Client::new();

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    // Build the shared application state
    let state = AppState {
        config: config.clone(),
        client,
        base_url,
        enterprise_features: config.enterprise_features,
        license_jwt_secret,
    };
    // Create middleware layer that validates API keys & enforces quotas
    let auth_layer = axum::middleware::from_fn_with_state(state.clone(), validate_license_jwt);

    // Public routes (no auth)
    let public_routes = Router::new()
        .route("/health", axum::routing::get(routes::health_check))
        .route("/debug/multipart", post(routes::debug_multipart));

    // Protected routes (with auth)
    let protected_routes = Router::new()
        .route("/binary/analyze", post(routes::upload_and_analyze_binary))
        .route("/binary/diff", post(routes::diff_binaries))
        .route(
            "/binary/attest",
            post(enterprise::attestation::attest_binary),
        )
        .route("/binary/check-cves", post(routes::check_cve))
        .route_layer(auth_layer);

    // Build the main app router
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", port)).await?;

    tracing::info!("Server starting on port {}", port);
    tracing::info!(
        "Deployment: {:?}, Enterprise features: {}",
        config.deployment_type,
        config.enterprise_features
    );

    axum::serve(listener, app).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use cli::{Commands, NablaCli};

    // Parse command line arguments
    #[derive(Parser)]
    #[command(name = "nabla")]
    #[command(about = "Nabla Binary Analysis & Security Platform")]
    struct Cli {
        #[command(subcommand)]
        command: Option<Commands>,

        /// Run in server mode (legacy)
        #[arg(long)]
        server: bool,

        /// Port for server mode
        #[arg(long, default_value = "8080")]
        port: u16,
    }

    let cli = Cli::parse();

    // Handle legacy --server flag
    if cli.server {
        return run_server(cli.port).await;
    }

    // Handle CLI commands
    match cli.command {
        Some(command) => {
            let mut nabla_cli = NablaCli::new()?;
            nabla_cli.handle_command(command).await
        }
        None => {
            // Show help when no command is provided
            let nabla_cli = NablaCli::new()?;
            nabla_cli.show_intro_and_help().await
        }
    }
}
