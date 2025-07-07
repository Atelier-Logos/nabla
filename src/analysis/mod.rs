pub mod cargo_audit;
pub mod cargo_metadata;
pub mod source_analyzer;
pub mod documentation;
pub mod unsafe_detector;
pub mod license_analyzer;
pub mod git_analyzer;
pub mod llm_enricher;

use std::path::Path;
use tokio::process::Command as TokioCommand;
use crate::models::PackageAnalysis;
use anyhow::Result;
use chrono::{DateTime, Utc};
use crate::models::AnalyzeRequest;
use std::process::Command;
use std::collections::HashMap;
use serde_json::json;
use crate::database::DatabasePool;
use anyhow::{Context, anyhow};
use reqwest::header::{USER_AGENT, ACCEPT};
use serde::Deserialize;
use std::io::Cursor;
use flate2::read::GzDecoder;
use tar::Archive;

pub struct PackageAnalyzer {
    _temp_dir: tempfile::TempDir,
    package_path: std::path::PathBuf,
}

impl PackageAnalyzer {
    pub async fn new(name: &str, version: &str) -> Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let package_path = temp_dir.path().join(format!("{}-{}", name, version));
        
        // Download and extract the package
        Self::download_package(name, version, &package_path).await?;
        
        Ok(Self {
            _temp_dir: temp_dir,
            package_path,
        })
    }

    pub async fn analyze(&self, request: &AnalyzeRequest, key_id: uuid::Uuid) -> Result<PackageAnalysis> {
        tracing::info!("Starting analysis for {}:{}", request.name, request.version);

        // Run all analyses in parallel where possible
        let (
            metadata_result,
            audit_result,
            source_analysis,
            docs_analysis,
            unsafe_analysis,
            license_analysis,
            git_analysis,
            crate_info
        ) = tokio::try_join!(
            cargo_metadata::analyze(&self.package_path),
            cargo_audit::analyze(&self.package_path),
            source_analyzer::analyze(&self.package_path, &request.extraction_depth),
            documentation::analyze(&self.package_path),
            unsafe_detector::analyze(&self.package_path),
            license_analyzer::analyze(&self.package_path),
            git_analyzer::analyze(&self.package_path),
            fetch_crates_io_info(&request.name, &request.version)
        )?;

        // If git_analysis didn't return commit dates, try GitHub API (best-effort, non-fatal)
        let github_commit = if git_analysis.last_commit.is_none() {
            if let Some(repo_url) = &metadata_result.repository {
                fetch_latest_github_commit(repo_url).await.ok().flatten()
            } else { None }
        } else { None };

        // Read Cargo.toml if it exists
        let cargo_toml = self.read_cargo_toml().await.ok();

        // Construct the final analysis result
        let mut analysis = PackageAnalysis {
            package_name: request.name.clone(),
            version: request.version.clone(),
            extraction_depth: request.extraction_depth.clone(),
            description: metadata_result.description,
            downloads: crate_info.downloads,
            repository: metadata_result.repository,
            homepage: metadata_result.homepage,
            documentation: metadata_result.documentation,
            key_modules: source_analysis.key_modules,
            important_structs: source_analysis.important_structs,
            notable_functions: source_analysis.notable_functions,
            traits: source_analysis.traits,
            features: metadata_result.features,
            api_usage_examples: source_analysis.api_examples,
            dependency_graph: metadata_result.dependencies,
            updated_at: Utc::now(),
            cargo_toml,
            source: source_analysis.source_stats,
            docs_quality_score: docs_analysis.quality_score,
            last_git_commit: git_analysis.last_commit.or(github_commit),
            publish_date: git_analysis.publish_date.or(crate_info.publish_date),
            cargo_audit_report: audit_result.report,
            unsafe_usage_locations: unsafe_analysis.locations,
            uses_unsafe: unsafe_analysis.uses_unsafe,
            licenses: license_analysis.licenses,
            macro_usage: source_analysis.macro_usage,
            build_rs_present: source_analysis.build_rs_present,
            public_api_surface: source_analysis.public_api_surface,
            known_cve_references: audit_result.cve_references,
            external_crates_used: source_analysis.external_crates,
            cache_expires_at: request.cache_expires_at,
            key_id,
        };

        // Enrich with LLM (best-effort; errors are logged inside function)
        llm_enricher::enrich_analysis(&mut analysis).await.ok();

        tracing::info!("Analysis completed for {}:{}", request.name, request.version);
        Ok(analysis)
    }

    async fn download_package(name: &str, version: &str, target_path: &Path) -> Result<()> {
        tracing::debug!("Downloading package {}:{} to {:?}", name, version, target_path);
        
        // Create parent directory
        if let Some(parent) = target_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Download from crates.io
        let url = format!("https://crates.io/api/v1/crates/{}/{}/download", name, version);
        tracing::debug!("Downloading from URL: {}", url);
        
        let response = reqwest::get(&url).await?;
        
        if !response.status().is_success() {
            anyhow::bail!("Failed to download package: HTTP {}", response.status());
        }
        
        let bytes = response.bytes().await?;
        tracing::debug!("Downloaded {} bytes", bytes.len());
        
        // Extract the tarball in-process (no external `tar` needed)
        let gz = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(gz);
        archive.unpack(target_path.parent().unwrap())
            .with_context(|| "Failed to extract .crate tarball")?;

        tracing::debug!("Successfully extracted package to {:?}", target_path);

        // Verify the extraction worked
        let cargo_toml_path = target_path.join("Cargo.toml");
        if !cargo_toml_path.exists() {
            // List what was actually extracted
            let entries = tokio::fs::read_dir(target_path.parent().unwrap()).await?;
            let mut entry_names = Vec::new();
            let mut entries = entries;
            while let Some(entry) = entries.next_entry().await? {
                entry_names.push(entry.file_name().to_string_lossy().to_string());
            }
            
            tracing::error!("Cargo.toml not found at {:?}", cargo_toml_path);
            tracing::error!("Directory contents: {:?}", entry_names);
            
            anyhow::bail!("Package extraction failed: Cargo.toml not found");
        }

        Ok(())
    }

    async fn read_cargo_toml(&self) -> Result<String> {
        let cargo_toml_path = self.package_path.join("Cargo.toml");
        let content = tokio::fs::read_to_string(cargo_toml_path).await?;
        Ok(content)
    }
}

// ---------------- Helper utilities ----------------

#[derive(Default)]
struct CrateInfo {
    downloads: Option<i64>,
    publish_date: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct CratesIoVersionResponse {
    version: CratesIoVersion,
}

#[derive(Deserialize)]
struct CratesIoVersion {
    downloads: i64,
    created_at: String,
}

async fn fetch_crates_io_info(name: &str, version: &str) -> Result<CrateInfo> {
    let client = reqwest::Client::new();
    let url = format!("https://crates.io/api/v1/crates/{}/{}", name, version);
    let resp = client
        .get(&url)
        .header(USER_AGENT, "ferropipe-audit")
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        tracing::warn!("crates.io rate limited; falling back to crate summary endpoint");
    }

    let (downloads, created_at) = if resp.status().is_success() {
        let data: CratesIoVersionResponse = resp.json().await?;
        (Some(data.version.downloads), Some(data.version.created_at))
    } else {
        // fallback to /crates/{name}
        let url2 = format!("https://crates.io/api/v1/crates/{}", name);
        let resp2 = client
            .get(&url2)
            .header(USER_AGENT, "ferropipe-audit")
            .send()
            .await?;
        if !resp2.status().is_success() {
            return Ok(CrateInfo::default());
        }
        #[derive(Deserialize)]
        struct CrateResponse { krate: CrateInner }
        #[derive(Deserialize)]
        struct CrateInner { downloads: i64, created_at: String }
        let data: CrateResponse = resp2.json().await?;
        (Some(data.krate.downloads), Some(data.krate.created_at))
    };

    tracing::debug!("crates.io downloads: {:?} created_at: {:?}", downloads, created_at);

    let publish_date = created_at
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    Ok(CrateInfo {
        downloads,
        publish_date,
    })
}

async fn fetch_latest_github_commit(repo_url: &str) -> Result<Option<DateTime<Utc>>> {
    // Expect URL like https://github.com/owner/repo or https://github.com/owner/repo.git
    if !repo_url.contains("github.com") {
        return Ok(None);
    }
    let parts: Vec<&str> = repo_url
        .trim_end_matches(".git")
        .split('/')
        .collect();
    if parts.len() < 5 {
        return Ok(None);
    }
    let owner = parts[3];
    let repo = parts[4];
    let api_url = format!("https://api.github.com/repos/{}/{}/commits?per_page=1", owner, repo);

    let client = reqwest::Client::new();
    let resp = client
        .get(&api_url)
        .header(USER_AGENT, "ferropipe-audit")
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let commits: serde_json::Value = resp.json().await?;
    if let Some(first) = commits.as_array().and_then(|arr| arr.first()) {
        if let Some(date_str) = first
            .get("commit")
            .and_then(|c| c.get("author"))
            .and_then(|a| a.get("date"))
            .and_then(|d| d.as_str())
        {
            if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
                return Ok(Some(dt.with_timezone(&Utc)));
            }
        }
    }
    Ok(None)
} 