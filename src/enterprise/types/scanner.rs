use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use nabla_core::{SeverityLevel, ConfidenceLevel, CodeLocation};

// Scanner-specific analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    pub analysis_id: Uuid,
    pub file_path: String,
    pub unsafe_functions: Vec<UnsafeFunctionFinding>,
    pub memory_issues: Vec<MemoryIssueFinding>,
    pub system_calls: Vec<SystemCallFinding>,
    pub hardening_issues: Vec<HardeningFinding>,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeFunctionFinding {
    pub function_name: String,
    pub location: CodeLocation,
    pub risk_level: SeverityLevel,
    pub description: String,
    pub alternatives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryIssueFinding {
    pub issue_type: MemoryIssueType,
    pub location: CodeLocation,
    pub severity: SeverityLevel,
    pub description: String,
    pub vulnerable_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryIssueType {
    BufferOverflow,
    UseAfterFree,
    DoubleFree,
    MemoryLeak,
    IntegerOverflow,
    UnboundedRead,
    UnboundedWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCallFinding {
    pub syscall_name: String,
    pub location: CodeLocation,
    pub danger_level: SeverityLevel,
    pub reason: String,
    pub mitigation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningFinding {
    pub hardening_feature: String,
    pub status: HardeningStatus,
    pub recommendation: String,
    pub impact: SeverityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardeningStatus {
    Missing,
    Weak,
    Misconfigured,
    Present,
}

// Behavioral Analysis Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysisResult {
    pub analysis_id: Uuid,
    pub file_path: String,
    pub control_flow_anomalies: Vec<ControlFlowAnomaly>,
    pub network_patterns: Vec<NetworkPattern>,
    pub data_flow_issues: Vec<DataFlowIssue>,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowAnomaly {
    pub anomaly_type: ControlFlowAnomalyType,
    pub location: CodeLocation,
    pub confidence: ConfidenceLevel,
    pub description: String,
    pub call_graph_fragment: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlFlowAnomalyType {
    UnexpectedJump,
    SuspiciousLoop,
    DeadCode,
    HiddenBranch,
    AntiDebugPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPattern {
    pub pattern_type: NetworkPatternType,
    pub endpoints: Vec<String>,
    pub frequency: Option<u32>,
    pub suspicious_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPatternType {
    Beaconing,
    DataExfiltration,
    CommandAndControl,
    DNSTunneling,
    SuspiciousPort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowIssue {
    pub issue_type: DataFlowIssueType,
    pub source: CodeLocation,
    pub sink: CodeLocation,
    pub severity: SeverityLevel,
    pub data_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataFlowIssueType {
    UncontrolledInput,
    DataLeakage,
    PrivilegeEscalation,
    UnsanitizedOutput,
}

// Cryptographic Analysis Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAnalysisResult {
    pub analysis_id: Uuid,
    pub file_path: String,
    pub key_issues: Vec<KeyIssue>,
    pub algorithm_issues: Vec<AlgorithmIssue>,
    pub implementation_issues: Vec<CryptoImplementationIssue>,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyIssue {
    pub issue_type: KeyIssueType,
    pub location: CodeLocation,
    pub severity: SeverityLevel,
    pub key_material: Option<String>, // Redacted/hashed for security
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyIssueType {
    HardcodedKey,
    WeakKey,
    KeyReuse,
    InsecureKeyGeneration,
    KeyInPlaintext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmIssue {
    pub algorithm_name: String,
    pub issue_type: AlgorithmIssueType,
    pub location: CodeLocation,
    pub severity: SeverityLevel,
    pub replacement_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlgorithmIssueType {
    Deprecated,
    Weak,
    Broken,
    Misconfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoImplementationIssue {
    pub issue_description: String,
    pub location: CodeLocation,
    pub severity: SeverityLevel,
    pub cwe_id: Option<String>,
}

// Supply Chain Analysis Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainAnalysisResult {
    pub analysis_id: Uuid,
    pub file_path: String,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub build_anomalies: Vec<BuildAnomaly>,
    pub dependency_issues: Vec<DependencyIssue>,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPattern {
    pub pattern_id: String,
    pub pattern_type: MaliciousPatternType,
    pub location: CodeLocation,
    pub confidence: ConfidenceLevel,
    pub description: String,
    pub yara_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaliciousPatternType {
    KnownMalware,
    Backdoor,
    Obfuscation,
    AntiAnalysis,
    SuspiciousString,
    HiddenFunctionality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAnomaly {
    pub anomaly_type: BuildAnomalyType,
    pub description: String,
    pub severity: SeverityLevel,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuildAnomalyType {
    UnexpectedCompiler,
    SuspiciousBuildFlags,
    ModifiedTimestamps,
    UnknownToolchain,
    CompromisedBuildEnvironment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyIssue {
    pub dependency_name: String,
    pub issue_type: DependencyIssueType,
    pub severity: SeverityLevel,
    pub description: String,
    pub source_location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencyIssueType {
    Outdated,
    Vulnerable,
    Suspicious,
    Malicious,
    Unlicensed,
}

// Exploitability Analysis Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityAnalysisResult {
    pub analysis_id: Uuid,
    pub file_path: String,
    pub attack_vectors: Vec<AttackVector>,
    pub reachability_analysis: Vec<ReachabilityPath>,
    pub privilege_analysis: Vec<PrivilegeEscalationPath>,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackVector {
    pub vector_id: String,
    pub vector_type: AttackVectorType,
    pub entry_point: CodeLocation,
    pub target: CodeLocation,
    pub exploitability_score: f32,
    pub prerequisites: Vec<String>,
    pub impact: ExploitImpact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackVectorType {
    BufferOverflow,
    IntegerOverflow,
    FormatString,
    UseAfterFree,
    RaceCondition,
    CommandInjection,
    PathTraversal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitImpact {
    pub confidentiality: ImpactLevel,
    pub integrity: ImpactLevel,
    pub availability: ImpactLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityPath {
    pub vulnerability_id: String,
    pub is_reachable: bool,
    pub path: Vec<String>,
    pub confidence: ConfidenceLevel,
    pub conditions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEscalationPath {
    pub path_id: String,
    pub source_privilege: String,
    pub target_privilege: String,
    pub steps: Vec<EscalationStep>,
    pub feasibility: ConfidenceLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationStep {
    pub step_description: String,
    pub location: CodeLocation,
    pub required_conditions: Vec<String>,
}

// Aggregated scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveScanResult {
    pub scan_id: Uuid,
    pub file_path: String,
    pub static_analysis: Option<StaticAnalysisResult>,
    pub behavioral_analysis: Option<BehavioralAnalysisResult>,
    pub crypto_analysis: Option<CryptoAnalysisResult>,
    pub supply_chain_analysis: Option<SupplyChainAnalysisResult>,
    pub exploitability_analysis: Option<ExploitabilityAnalysisResult>,
    pub total_duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}