use axum::{
    http::{header, Method},
    routing::post,
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use axum::extract::DefaultBodyLimit;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use dotenvy::dotenv;

mod config;
mod routes;
mod database;
mod middleware;
mod binary;

use config::Config;
use database::DatabasePool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env if available
    dotenv().ok();

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
    
    // Initialize database pool
    let pool = DatabasePool::new(&config.database_url).await?;
    
    // Skip migrations since tables already exist
    // sqlx::migrate!("./migrations").run(&pool.pool).await?;

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    // Build the shared application state
    let state = AppState { pool, config: config.clone() };

    // Create middleware layer that validates API keys & enforces quotas
    let auth_layer = axum::middleware::from_fn_with_state(state.clone(), middleware::validate_api_key);

    // Public routes (no auth)
    let public_routes = Router::new()
        .route("/health", axum::routing::get(routes::health_check))
        .route("/debug/multipart", post(routes::debug_multipart));

    // Protected routes (with auth)
    let protected_routes = Router::new()
        .route("/binary/analyze", post(routes::upload_and_analyze_binary))
        .route("/binary/diff", post(routes::diff_binaries))
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

#[derive(Clone)]
pub struct AppState {
    pub pool: DatabasePool,
    pub config: Config,
} 