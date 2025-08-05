// src/lib.rs
use std::sync::Arc;
pub mod binary;
pub mod config;
pub mod middleware;
pub mod routes;
pub mod ssrf_protection; // Add SSRF protection module
// pub mod providers; // Using enterprise providers instead
pub mod cli;
pub mod enterprise;

// Re-export AppState so integration tests can build routers easily.
pub use config::Config;
use reqwest::Client;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub client: Client,
    pub base_url: String,
    pub enterprise_features: bool,
    pub license_jwt_secret: Arc<[u8; 32]>,
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

        // Use consistent key loading from config
        let key_b64 = config.license_signing_key.clone();

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim())?;
        let secret_array: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("LICENSE_SIGNING_KEY must be exactly 32 bytes"))?;
        let license_jwt_secret = Arc::new(secret_array);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "nabla=debug,tower_http=debug".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // disable redirects for SSRF protection
            .build()?;


        let state = crate::AppState {
            config: config.clone(),
            client,
            base_url: config.base_url.clone(),
            enterprise_features: config.enterprise_features,
            license_jwt_secret,
        };

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

        // Create middleware layer that validates API keys & enforces quotas
        let auth_layer = axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::validate_license_jwt,
        );

        // Public routes (no auth)
        let public_routes = Router::new().route(
            "/health",
            axum::routing::get(crate::routes::binary::health_check),
        );

        // Protected routes (with auth)
        let protected_routes = Router::new()
            .route(
                "/binary/analyze",
                post(crate::routes::binary::upload_and_analyze_binary),
            )
            .route("/binary/diff", post(crate::routes::binary::diff_binaries))
            .route(
                "/binary/attest",
                post(crate::enterprise::attestation::attest_binary),
            )
            .route("/binary/check-cves", post(crate::routes::binary::check_cve))
            .route_layer(auth_layer);

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
