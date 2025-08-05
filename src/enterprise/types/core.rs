use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildResult {
    pub success: bool,
    pub output_path: Option<String>,
    pub target_format: Option<String>,
    pub error_output: Option<String>,
    pub build_system: BuildSystem,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuildSystem {
    Cargo,
    Makefile,
    CMake,
    PlatformIO,
    ZephyrWest,
    STM32CubeIDE,
    SCons,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfiguration {
    pub severity_threshold: SeverityLevel,
    pub include_cve_data: bool,
    pub generate_attestation: bool,
    pub binary_formats: Vec<BinaryFormat>,
    pub advanced_config: Option<AdvancedScanConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedScanConfig {
    pub enable_static_analysis: bool,
    pub enable_behavioral_analysis: bool,
    pub enable_crypto_analysis: bool,
    pub enable_supply_chain_detection: bool,
    pub enable_exploitability_analysis: bool,
    pub custom_yara_rules: Option<Vec<String>>,
    pub max_analysis_depth: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinaryFormat {
    ELF,
    PE,
    MachO,
    IntelHex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub file_path: String,
    pub file_hash: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub checks: Vec<SecurityCheck>,
    pub findings: Vec<ScanFinding>,
    pub scan_duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: SeverityLevel,
    pub title: String,
    pub description: String,
    pub cve_id: Option<String>,
    pub reachability: ExploitabilityAnalysis,
    pub category: VulnerabilityCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityAnalysis {
    pub is_reachable: bool,
    pub path: Option<Vec<String>>,
    pub sink: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCheck {
    pub check_id: String,
    pub name: String,
    pub description: String,
    pub status: CheckStatus,
    pub severity: Option<SeverityLevel>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckStatus {
    Pass,
    Fail,
    Error(String),
    Skip(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubApp {
    pub id: Uuid,
    pub app_id: i64,
    pub private_key: String,
    pub github_api_base: String,
    pub webhook_secret: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubInstallation {
    pub id: Uuid,
    pub github_app_id: Uuid,
    pub installation_id: i64,
    pub account_login: String,
    pub account_type: String,
    pub permissions: HashMap<String, String>,
    pub events: Vec<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub suspended_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub github_account_login: String,
    pub events: Vec<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Advanced scanning types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilityCategory {
    CVE,
    StaticAnalysis,
    Behavioral,
    Cryptographic,
    SupplyChain,
    Exploitability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: String,
    pub category: FindingCategory,
    pub severity: SeverityLevel,
    pub title: String,
    pub description: String,
    pub location: Option<CodeLocation>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub confidence: ConfidenceLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    StaticAnalysis(StaticAnalysisType),
    Behavioral(BehavioralType),
    Cryptographic(CryptoType),
    SupplyChain(SupplyChainType),
    Exploitability(ExploitabilityType),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StaticAnalysisType {
    UnsafeFunction,
    MemoryVulnerability,
    DangerousSystemCall,
    MissingSecurityHardening,
    BufferOverflow,
    IntegerOverflow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehavioralType {
    SuspiciousControlFlow,
    NetworkBeaconing,
    DataExfiltration,
    UnexpectedSystemInteraction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoType {
    HardcodedKey,
    WeakAlgorithm,
    DeprecatedCipher,
    InsecureRandomness,
    KeyReuse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupplyChainType {
    MaliciousBytePattern,
    HiddenFunctionality,
    BuildMetadataAnomaly,
    SuspiciousImport,
    Backdoor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExploitabilityType {
    ReachableVulnerability,
    PrivilegeEscalation,
    RemoteCodeExecution,
    DataLeakage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file_path: String,
    pub line_number: Option<u32>,
    pub column_number: Option<u32>,
    pub function_name: Option<String>,
    pub binary_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Critical,
}
