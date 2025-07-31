// src/binary/mod.rs
pub mod binary_analysis;
pub mod check_vulnerabilities;
pub mod metadata_extractor;

pub use self::binary_analysis::analyze_binary;
pub use self::check_vulnerabilities::{VulnerabilityMatch, scan_binary_vulnerabilities};
pub use self::metadata_extractor::{
    LicenseInfo, VersionInfo, extract_license_info, extract_version_info,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BinaryAnalysis {
    pub id: Uuid,
    pub file_name: String,
    pub format: String,
    pub architecture: String,
    pub languages: Vec<String>,
    pub detected_symbols: Vec<String>,
    pub embedded_strings: Vec<String>,
    pub suspected_secrets: Vec<String>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub hash_sha256: String,
    pub hash_blake3: Option<String>,
    pub size_bytes: u64,
    pub linked_libraries: Vec<String>,
    pub static_linked: bool,
    pub version_info: Option<VersionInfo>,
    pub license_info: Option<LicenseInfo>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub sbom: Option<serde_json::Value>,
}
