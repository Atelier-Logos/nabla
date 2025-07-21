// src/lib.rs

pub mod config;
pub mod routes;
pub mod database;
pub mod middleware;
pub mod binary;

// Re-export AppState so integration tests can build routers easily.
use config::Config;
use database::DatabasePool;

#[derive(Clone)]
pub struct AppState {
    pub pool: DatabasePool,
    pub config: Config,
}

// For binary crate main.rs we still have its own AppState; To avoid duplication, we
// `cfg`-gate one of them, but duplicate struct definition is okay across crates
// as they live in different crates (bin vs lib). 