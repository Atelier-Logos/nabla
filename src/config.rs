use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub port: u16,
    pub base_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        
        let config = Config {
            port: std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse()?,
            base_url: std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
        };

        Ok(config)
    }
} 