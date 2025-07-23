use axum::{
    http::{header, Method},
    routing::post,
    Router,
};
use tokio::spawn;
use tower_http::cors::{Any, CorsLayer};
use axum::extract::DefaultBodyLimit;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use dotenvy::dotenv;
use reqwest::Client; // Add import for Client
use base64::engine::general_purpose;
use base64::Engine;
use std::sync::Arc;

mod config;
mod routes;
mod middleware;
mod binary;

use config::Config;
use middleware::validate_license_jwt;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub client: Client, // Add client field
    pub base_url: String, // Add base_url field
    pub license_jwt_secret: Arc<[u8; 32]>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env if available
    dotenv().ok();

    let key_b64 = std::env::var("LICENSE_SIGNING_KEY").expect("LICENSE_SIGNING_KEY env missing");
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim())?;
    let secret_array: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("LICENSE_SIGNING_KEY must be exactly 32 bytes"))?;
    let license_jwt_secret = Arc::new(secret_array);

    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nabla=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    // Initialize license client
    let client = Client::new();

    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    // Skip migrations since tables already exist

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
        .route("/binary/attest", post(binary::attest_binary))
        .route("/binary/check-cves", post(routes::check_cve))
        .route_layer(auth_layer);

    // Build the main app router
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", config.port)).await?;
    
    tracing::info!("Server starting on port {}", config.port);
    
    axum::serve(listener, app).await?;

    Ok(())
}