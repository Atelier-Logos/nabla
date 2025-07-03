use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub supabase_url: String,
    pub supabase_anon_key: String,
    pub api_key_table: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        
        let config = Config {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/ferropipe_audit".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3001".to_string())
                .parse()?,
            supabase_url: std::env::var("SUPABASE_URL")
                .expect("SUPABASE_URL must be set"),
            supabase_anon_key: std::env::var("SUPABASE_ANON_KEY")
                .expect("SUPABASE_ANON_KEY must be set"),
            api_key_table: std::env::var("API_KEY_TABLE")
                .unwrap_or_else(|_| "api_keys".to_string()),
        };

        Ok(config)
    }
} 