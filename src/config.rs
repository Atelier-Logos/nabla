use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub port: u16,
    pub base_url: String,
    pub fips_mode: bool,
    pub fips_validation: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        
        let config = Config {
            port: std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse()?,
            base_url: std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
            fips_mode: std::env::var("FIPS_MODE").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            fips_validation: std::env::var("FIPS_VALIDATION").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        };

        Ok(config)
    }
} 