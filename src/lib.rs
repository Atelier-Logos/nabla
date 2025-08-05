// src/lib.rs
use std::sync::Arc;
pub mod binary;
pub mod config;
pub mod middleware;
pub mod routes;
pub mod ssrf_protection; // Add SSRF protection module
// pub mod providers; // Using enterprise providers instead
pub mod cli;

// Re-export AppState so integration tests can build routers easily.
pub use config::Config;
use reqwest::Client;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub client: Client,
    pub base_url: String,
}

// For binary crate main.rs we still have its own AppState; To avoid duplication, we
// `cfg`-gate one of them, but duplicate struct definition is okay across crates
// as they live in different crates (bin vs lib).

// Re-export the server function from the binary crate
pub mod server {
    pub async fn run_server(port: u16) -> anyhow::Result<()> {
        use axum::extract::DefaultBodyLimit;
        use axum::{
            Router,
            http::{Method, header},
            routing::post,
        };
        use base64::Engine;
        use dotenvy::dotenv;
        use std::sync::Arc;
        use tower_http::cors::{Any, CorsLayer};
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        dotenv().ok();
        let config = crate::Config::from_env()?;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // disable redirects for SSRF protection
            .build()?;

        let state = crate::AppState {
            config: config.clone(),
            client,
            base_url: config.base_url.clone(),
        };

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

        // Public routes (no auth)
        let public_routes = Router::new().route(
            "/health",
            axum::routing::get(crate::routes::binary::health_check),
        );

        // All routes are now public
        let protected_routes = Router::new()
            .route(
                "/binary/analyze",
                post(crate::routes::binary::upload_and_analyze_binary),
            )
            .route("/binary/diff", post(crate::routes::binary::diff_binaries))
            .route("/binary/check-cves", post(crate::routes::binary::check_cve));

        let app = Router::new()
            .merge(public_routes)
            .merge(protected_routes)
            .layer(cors)
            .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", port)).await?;
        tracing::info!("Server starting on port {}", port);

        axum::serve(listener, app).await?;
        Ok(())
    }
}
