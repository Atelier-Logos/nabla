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

    pub async fn insert_package_analysis(&self, package: &crate::models::PackageAnalysis) -> Result<Uuid> {
        let id = Uuid::new_v4();
        
        sqlx::query(
            r#"
            INSERT INTO packages (
                id, package_name, version, description, downloads,
                repository, homepage, documentation, key_modules, important_structs,
                notable_functions, traits, features, api_usage_examples, dependency_graph,
                updated_at, cargo_toml, source, docs_quality_score, last_git_commit,
                key_id, publish_date, cargo_audit_report, unsafe_usage_locations,
                uses_unsafe, "license(s)", macro_usage, build_rs_present, public_api_surface,
                known_cve_references, external_crates_used, cache_expires_at, sbom
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34
            )
            "#
        )
        .bind(&id)
        .bind(&package.package_name)
        .bind(&package.version)
        .bind(&package.description)
        .bind(&package.downloads)
        .bind(&package.repository)
        .bind(&package.homepage)
        .bind(&package.documentation)
        .bind(&package.key_modules)
        .bind(&package.important_structs)
        .bind(&package.notable_functions)
        .bind(&package.traits)
        .bind(&package.features)
        .bind(&package.api_usage_examples)
        .bind(&package.dependency_graph)
        .bind(&package.updated_at)
        .bind(&package.cargo_toml)
        .bind(&package.source)
        .bind(&package.docs_quality_score)
        .bind(&package.last_git_commit)
        .bind(&package.key_id)
        .bind(&package.publish_date)
        .bind(&package.cargo_audit_report)
        .bind(&package.unsafe_usage_locations)
        .bind(&package.uses_unsafe)
        .bind(&package.licenses)
        .bind(&package.macro_usage)
        .bind(&package.build_rs_present)
        .bind(&package.public_api_surface)
        .bind(&package.known_cve_references)
        .bind(&package.external_crates_used)
        .bind(&package.cache_expires_at)
        .bind(&package.sbom)
        .execute(&self.pool)
        .await?;

        // store the full analysis JSON for quick fetch endpoint
        let full_json = serde_json::to_value(package)?;
        sqlx::query("UPDATE packages SET full_analysis = $2 WHERE id = $1")
            .bind(&id)
            .bind(&full_json)
            .execute(&self.pool)
            .await?;

        Ok(id)
    }

    pub async fn get_full_analysis(&self, id: &uuid::Uuid) -> Result<Option<serde_json::Value>> {
        let row = sqlx::query("SELECT full_analysis FROM packages WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            let json: serde_json::Value = row.get("full_analysis");
            Ok(Some(json))
        } else {
            Ok(None)
        }
    }
} 