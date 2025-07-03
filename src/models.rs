use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::types::JsonValue;

#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    pub name: String,
    pub version: String,
    pub api_key: String,
    pub extraction_depth: String,
    pub cache_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub success: bool,
    pub package_id: Option<Uuid>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PackageAnalysis {
    pub package_name: String,
    pub version: String,
    pub extraction_depth: String,
    pub description: Option<String>,
    pub downloads: Option<i64>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
    pub key_modules: JsonValue,
    pub important_structs: JsonValue,
    pub notable_functions: JsonValue,
    pub traits: JsonValue,
    pub features: JsonValue,
    pub api_usage_examples: JsonValue,
    pub dependency_graph: JsonValue,
    pub updated_at: DateTime<Utc>,
    pub cargo_toml: Option<String>,
    pub source: JsonValue,
    pub docs_quality_score: JsonValue,
    pub last_git_commit: Option<DateTime<Utc>>,
    pub key_id: Uuid,
    pub publish_date: Option<DateTime<Utc>>,
    pub cargo_audit_report: JsonValue,
    pub unsafe_usage_locations: JsonValue,
    pub uses_unsafe: bool,
    pub licenses: JsonValue,
    pub macro_usage: JsonValue,
    pub build_rs_present: bool,
    pub public_api_surface: i64,
    pub known_cve_references: JsonValue,
    pub external_crates_used: Vec<String>,
    pub cache_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CargoMetadata {
    pub packages: Vec<CargoPackage>,
    pub dependencies: JsonValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CargoPackage {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
    pub license: Option<String>,
    pub features: JsonValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub vulnerabilities: JsonValue,
    pub warnings: JsonValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsafeUsage {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub context: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocsQuality {
    pub coverage_percentage: f64,
    pub missing_docs: Vec<String>,
    pub doc_comments_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MacroUsage {
    pub macro_name: String,
    pub usage_count: usize,
    pub locations: Vec<String>,
} 