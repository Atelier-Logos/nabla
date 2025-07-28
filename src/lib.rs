// src/lib.rs
use std::sync::Arc;
pub mod config;
pub mod routes;
pub mod middleware;
pub mod binary;
pub mod providers;
pub mod enterprise;
#[path = "enterprise/crypto/mod.rs"]  
pub mod crypto;

// Re-export AppState so integration tests can build routers easily.
pub use config::Config;
use reqwest::Client;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub client: Client,
    pub base_url: String,
    pub license_jwt_secret: Arc<[u8; 32]>,
    pub crypto_provider: enterprise::crypto::CryptoProvider,
}

// For binary crate main.rs we still have its own AppState; To avoid duplication, we
// `cfg`-gate one of them, but duplicate struct definition is okay across crates
// as they live in different crates (bin vs lib). 