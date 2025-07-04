use axum::{
    http::{header, Method},
    routing::post,
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use dotenvy::dotenv;

mod config;
mod models;
mod routes;
mod analysis;
mod database;

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
                .unwrap_or_else(|_| "ferropipe_audit=debug,tower_http=debug".into()),
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

    // Build the router
    let app = Router::new()
        .route("/analyze", post(routes::analyze_package))
        .route("/health", axum::routing::get(routes::health_check))
        .layer(cors)
        .with_state(AppState { pool, config: config.clone() });

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