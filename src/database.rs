use sqlx::{PgPool, Row};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;
use anyhow::Result;
use std::str::FromStr;

#[derive(Clone)]
pub struct DatabasePool {
    pub pool: PgPool,
}

impl DatabasePool {
    pub async fn new(database_url: &str) -> Result<Self> {
        let connect_options = PgConnectOptions::from_str(database_url)?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(connect_options)
            .await?;
        Ok(Self { pool })
    }

    pub async fn verify_api_key(&self, api_key: &str) -> Result<Option<Uuid>> {
        let row = sqlx::query(
            "SELECT id FROM api_keys WHERE api_key = $1 AND is_active = true"
        )
        .persistent(false)
        .bind(api_key)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let key_id: Uuid = row.get("id");
            Ok(Some(key_id))
        } else {
            Ok(None)
        }
    }
} 