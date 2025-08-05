// src/binary/mod.rs
pub mod binary_analysis;
pub mod metadata_extractor;
pub mod scanner;

pub use self::binary_analysis::analyze_binary;
pub use self::metadata_extractor::{
    LicenseInfo, VersionInfo, extract_license_info, extract_version_info,
};
pub use self::scanner::{ScanResult, enterprise_scan_binary, scan_binary};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CodeSection {
    pub name: String,
    pub start_address: u64,
    pub end_address: u64,
    pub size: u64,
    pub permissions: String, // e.g., "r-x", "rw-", etc.
    pub section_type: CodeSectionType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CodeSectionType {
    Text,   // Executable code
    Data,   // Initialized data
    Bss,    // Uninitialized data
    Rodata, // Read-only data
    Other(String),
}

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
    // Binary data for advanced analysis (CFG, disassembly, etc.)
    // Note: This field is marked with serde(skip) to avoid serialization overhead
    #[serde(skip)]
    pub binary_data: Option<Vec<u8>>,
    // Entry point information for CFG construction
    pub entry_point: Option<String>,
    // Code sections for targeted analysis
    pub code_sections: Vec<CodeSection>,
}
