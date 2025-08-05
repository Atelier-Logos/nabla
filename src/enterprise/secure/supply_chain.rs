#![allow(dead_code)]
use crate::binary::BinaryAnalysis;
use crate::enterprise::types::{CodeLocation, ConfidenceLevel, SeverityLevel};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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

pub fn analyze_supply_chain_security(analysis: &BinaryAnalysis) -> SupplyChainAnalysisResult {
    let start_time = Utc::now();

    let mut result = SupplyChainAnalysisResult {
        analysis_id: Uuid::new_v4(),
        file_path: analysis.file_name.clone(),
        malicious_patterns: Vec::new(),
        build_anomalies: Vec::new(),
        dependency_issues: Vec::new(),
        analysis_duration_ms: 0,
    };

    // Analyze for malicious patterns and indicators
    result.malicious_patterns = analyze_malicious_patterns(analysis);

    // Analyze build metadata for anomalies
    result.build_anomalies = analyze_build_anomalies(analysis);

    // Analyze dependencies for security issues
    result.dependency_issues = analyze_dependency_issues(analysis);

    let end_time = Utc::now();
    result.analysis_duration_ms = (end_time - start_time).num_milliseconds() as u64;

    result
}

fn analyze_malicious_patterns(analysis: &BinaryAnalysis) -> Vec<MaliciousPattern> {
    let mut patterns = Vec::new();

    // Known malware function signatures
    let malware_functions: HashMap<&str, (MaliciousPatternType, ConfidenceLevel, &str)> =
        HashMap::from([
            (
                "CreateRemoteThread",
                (
                    MaliciousPatternType::KnownMalware,
                    ConfidenceLevel::High,
                    "Process injection technique",
                ),
            ),
            (
                "WriteProcessMemory",
                (
                    MaliciousPatternType::KnownMalware,
                    ConfidenceLevel::High,
                    "Memory manipulation for injection",
                ),
            ),
            (
                "VirtualAllocEx",
                (
                    MaliciousPatternType::KnownMalware,
                    ConfidenceLevel::Medium,
                    "Remote memory allocation",
                ),
            ),
            (
                "SetWindowsHookEx",
                (
                    MaliciousPatternType::KnownMalware,
                    ConfidenceLevel::Medium,
                    "Windows hook injection",
                ),
            ),
            (
                "CreateToolhelp32Snapshot",
                (
                    MaliciousPatternType::AntiAnalysis,
                    ConfidenceLevel::Medium,
                    "Process enumeration",
                ),
            ),
            (
                "Module32First",
                (
                    MaliciousPatternType::AntiAnalysis,
                    ConfidenceLevel::Medium,
                    "Module enumeration",
                ),
            ),
            (
                "NtQuerySystemInformation",
                (
                    MaliciousPatternType::AntiAnalysis,
                    ConfidenceLevel::High,
                    "System information gathering",
                ),
            ),
            (
                "ZwQuerySystemInformation",
                (
                    MaliciousPatternType::AntiAnalysis,
                    ConfidenceLevel::High,
                    "Low-level system queries",
                ),
            ),
            (
                "RtlAdjustPrivilege",
                (
                    MaliciousPatternType::KnownMalware,
                    ConfidenceLevel::High,
                    "Privilege escalation",
                ),
            ),
            (
                "NtTerminateProcess",
                (
                    MaliciousPatternType::AntiAnalysis,
                    ConfidenceLevel::Medium,
                    "Process termination",
                ),
            ),
        ]);

    // Check imports and symbols for malicious functions
    for item in analysis
        .imports
        .iter()
        .chain(analysis.detected_symbols.iter())
    {
        if let Some((pattern_type, confidence, description)) = malware_functions.get(item.as_str())
        {
            patterns.push(MaliciousPattern {
                pattern_id: format!("FUNC_{}", item),
                pattern_type: pattern_type.clone(),
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(item.clone()),
                    binary_offset: None,
                },
                confidence: confidence.clone(),
                description: format!("Suspicious function: {} - {}", item, description),
                yara_rule: Some(format!(
                    "rule {} {{ strings: $func = \"{}\" condition: $func }}",
                    item, item
                )),
            });
        }
    }

    // Analyze embedded strings for malicious indicators
    for string in &analysis.embedded_strings {
        if let Some(pattern) = analyze_string_for_malicious_content(string, &analysis.file_name) {
            patterns.push(pattern);
        }
    }

    // Check for obfuscation patterns
    patterns.extend(detect_obfuscation_patterns(analysis));

    // Check for backdoor indicators
    patterns.extend(detect_backdoor_patterns(analysis));

    patterns
}

fn analyze_string_for_malicious_content(string: &str, file_path: &str) -> Option<MaliciousPattern> {
    let lower = string.to_lowercase();

    // Suspicious file paths and registry keys
    let suspicious_paths = [
        ("\\temp\\", "Temporary directory usage"),
        ("\\appdata\\roaming\\", "User roaming directory"),
        ("\\programdata\\", "System-wide data directory"),
        ("hkey_current_user", "Registry manipulation"),
        ("hkey_local_machine", "System registry access"),
        ("\\system32\\", "System directory access"),
        ("\\syswow64\\", "System directory access"),
    ];

    for (path, description) in &suspicious_paths {
        if lower.contains(path) {
            return Some(MaliciousPattern {
                pattern_id: format!("PATH_{}", path.replace("\\", "_")),
                pattern_type: MaliciousPatternType::SuspiciousString,
                location: CodeLocation {
                    file_path: file_path.to_string(),
                    line_number: None,
                    column_number: None,
                    function_name: None,
                    binary_offset: None,
                },
                confidence: ConfidenceLevel::Medium,
                description: format!("Suspicious path reference: {}", description),
                yara_rule: Some(format!(
                    "rule SuspiciousPath {{ strings: $path = \"{}\" nocase condition: $path }}",
                    path
                )),
            });
        }
    }

    // Suspicious commands and executables
    let suspicious_commands = [
        ("cmd.exe", "Command prompt execution"),
        ("powershell.exe", "PowerShell execution"),
        ("rundll32.exe", "DLL execution"),
        ("regsvr32.exe", "DLL registration"),
        ("schtasks.exe", "Task scheduler"),
        ("net.exe", "Network commands"),
        ("netsh.exe", "Network shell"),
    ];

    for (cmd, description) in &suspicious_commands {
        if lower.contains(cmd) {
            return Some(MaliciousPattern {
                pattern_id: format!("CMD_{}", cmd.replace(".", "_")),
                pattern_type: MaliciousPatternType::SuspiciousString,
                location: CodeLocation {
                    file_path: file_path.to_string(),
                    line_number: None,
                    column_number: None,
                    function_name: None,
                    binary_offset: None,
                },
                confidence: ConfidenceLevel::Medium,
                description: format!("Suspicious command reference: {}", description),
                yara_rule: Some(format!(
                    "rule SuspiciousCommand {{ strings: $cmd = \"{}\" nocase condition: $cmd }}",
                    cmd
                )),
            });
        }
    }

    // Network-related suspicious strings
    let network_indicators = [
        ("http://", "HTTP communication"),
        ("https://", "HTTPS communication"),
        ("ftp://", "FTP communication"),
        ("tcp://", "TCP communication"),
        ("udp://", "UDP communication"),
    ];

    for (indicator, description) in &network_indicators {
        if string.contains(indicator) && string.len() > 10 {
            // Check if it looks like a suspicious URL
            if is_suspicious_url(string) {
                return Some(MaliciousPattern {
                    pattern_id: "SUSPICIOUS_URL".to_string(),
                    pattern_type: MaliciousPatternType::SuspiciousString,
                    location: CodeLocation {
                        file_path: file_path.to_string(),
                        line_number: None,
                        column_number: None,
                        function_name: None,
                        binary_offset: None,
                    },
                    confidence: ConfidenceLevel::High,
                    description: format!("Suspicious URL detected: {}", description),
                    yara_rule: Some("rule SuspiciousURL { strings: $url = /https?:\\/\\/[^\\s]+/ condition: $url }".to_string()),
                });
            }
        }
    }

    // Check for encoded/obfuscated content
    if is_likely_obfuscated_string(string) {
        return Some(MaliciousPattern {
            pattern_id: "OBFUSCATED_STRING".to_string(),
            pattern_type: MaliciousPatternType::Obfuscation,
            location: CodeLocation {
                file_path: file_path.to_string(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            confidence: ConfidenceLevel::Medium,
            description: "Potentially obfuscated string detected".to_string(),
            yara_rule: None,
        });
    }

    None
}

fn detect_obfuscation_patterns(analysis: &BinaryAnalysis) -> Vec<MaliciousPattern> {
    let mut patterns = Vec::new();

    // Check for packing/obfuscation indicators
    let packer_strings = [
        "upx",
        "aspack",
        "pecompact",
        "petite",
        "nspack",
        "fsg",
        "mpress",
        "themida",
        "vmprotect",
    ];

    for string in &analysis.embedded_strings {
        let lower = string.to_lowercase();
        for packer in &packer_strings {
            if lower.contains(packer) {
                patterns.push(MaliciousPattern {
                    pattern_id: format!("PACKER_{}", packer.to_uppercase()),
                    pattern_type: MaliciousPatternType::Obfuscation,
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: None,
                        binary_offset: None,
                    },
                    confidence: ConfidenceLevel::High,
                    description: format!("Packer/Obfuscator detected: {}", packer),
                    yara_rule: Some(format!(
                        "rule Packer_{} {{ strings: $packer = \"{}\" nocase condition: $packer }}",
                        packer, packer
                    )),
                });
                break;
            }
        }
    }

    // Check for high entropy sections (potential packing)
    if analysis.embedded_strings.len() < 5 && analysis.size_bytes > 1024 {
        patterns.push(MaliciousPattern {
            pattern_id: "LOW_STRING_COUNT".to_string(),
            pattern_type: MaliciousPatternType::Obfuscation,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            confidence: ConfidenceLevel::Medium,
            description: "Unusually low string count for binary size - possible packing"
                .to_string(),
            yara_rule: None,
        });
    }

    patterns
}

fn detect_backdoor_patterns(analysis: &BinaryAnalysis) -> Vec<MaliciousPattern> {
    let mut patterns = Vec::new();

    // Check for backdoor-related network ports
    let backdoor_ports = [
        "31337", "12345", "54321", "4444", "5555", "6666", "7777", "8888", "9999",
    ];

    for string in &analysis.embedded_strings {
        for port in &backdoor_ports {
            if string.contains(port) {
                patterns.push(MaliciousPattern {
                    pattern_id: format!("BACKDOOR_PORT_{}", port),
                    pattern_type: MaliciousPatternType::Backdoor,
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: None,
                        binary_offset: None,
                    },
                    confidence: ConfidenceLevel::High,
                    description: format!("Backdoor port {} detected", port),
                    yara_rule: Some(format!(
                        "rule BackdoorPort_{} {{ strings: $port = \"{}\" condition: $port }}",
                        port, port
                    )),
                });
            }
        }
    }

    // Check for remote access tool (RAT) indicators
    let rat_indicators = [
        "remote desktop",
        "vnc",
        "teamviewer",
        "anydesk",
        "logmein",
        "pcanyware",
        "remote access",
        "backdoor",
        "trojan",
        "rat",
    ];

    for string in &analysis.embedded_strings {
        let lower = string.to_lowercase();
        for indicator in &rat_indicators {
            if lower.contains(indicator) {
                patterns.push(MaliciousPattern {
                    pattern_id: format!(
                        "RAT_INDICATOR_{}",
                        indicator.replace(" ", "_").to_uppercase()
                    ),
                    pattern_type: MaliciousPatternType::Backdoor,
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: None,
                        binary_offset: None,
                    },
                    confidence: ConfidenceLevel::Medium,
                    description: format!("Remote access tool indicator: {}", indicator),
                    yara_rule: Some(format!(
                        "rule RAT_Indicator {{ strings: $rat = \"{}\" nocase condition: $rat }}",
                        indicator
                    )),
                });
                break;
            }
        }
    }

    patterns
}

fn analyze_build_anomalies(analysis: &BinaryAnalysis) -> Vec<BuildAnomaly> {
    let mut anomalies = Vec::new();

    // Analyze build metadata if available
    if let Some(metadata) = analysis.metadata.as_object() {
        // Check for suspicious compiler information
        if let Some(compiler_info) = metadata.get("compiler") {
            let compiler_str = compiler_info.to_string().to_lowercase();

            // Check for unexpected compilers
            let suspicious_compilers = ["tcc", "lcc", "dmc", "unknown_compiler"];
            for compiler in &suspicious_compilers {
                if compiler_str.contains(compiler) {
                    let mut metadata_map = HashMap::new();
                    metadata_map.insert("compiler".to_string(), compiler_info.clone());

                    anomalies.push(BuildAnomaly {
                        anomaly_type: BuildAnomalyType::UnexpectedCompiler,
                        description: format!("Unexpected compiler detected: {}", compiler),
                        severity: SeverityLevel::Medium,
                        metadata: metadata_map,
                    });
                }
            }
        }

        // Check for suspicious build flags
        if let Some(build_flags) = metadata.get("build_flags") {
            let flags_str = build_flags.to_string().to_lowercase();

            let suspicious_flags = [
                ("-fno-stack-protector", "Stack protection disabled"),
                ("-z execstack", "Executable stack enabled"),
                ("-fno-pie", "Position independent executable disabled"),
                ("--disable-relro", "RELRO protection disabled"),
            ];

            for (flag, description) in &suspicious_flags {
                if flags_str.contains(flag) {
                    let mut metadata_map = HashMap::new();
                    metadata_map.insert(
                        "suspicious_flag".to_string(),
                        serde_json::Value::String(flag.to_string()),
                    );

                    anomalies.push(BuildAnomaly {
                        anomaly_type: BuildAnomalyType::SuspiciousBuildFlags,
                        description: format!("Suspicious build flag: {} - {}", flag, description),
                        severity: SeverityLevel::High,
                        metadata: metadata_map,
                    });
                }
            }
        }
    }

    // Check timestamp anomalies
    let current_time = Utc::now();
    let creation_time = analysis.created_at;

    // Check if binary claims to be from the future
    if creation_time > current_time {
        let mut metadata_map = HashMap::new();
        metadata_map.insert(
            "creation_time".to_string(),
            serde_json::Value::String(creation_time.to_rfc3339()),
        );
        metadata_map.insert(
            "current_time".to_string(),
            serde_json::Value::String(current_time.to_rfc3339()),
        );

        anomalies.push(BuildAnomaly {
            anomaly_type: BuildAnomalyType::ModifiedTimestamps,
            description: "Binary timestamp is in the future".to_string(),
            severity: SeverityLevel::Medium,
            metadata: metadata_map,
        });
    }

    // Check for signs of compromised build environment
    let compromised_indicators = [
        "/tmp/",
        "/var/tmp/",
        "C:\\Temp\\",
        "C:\\Windows\\Temp\\",
        "BuildAgent",
        "jenkins",
        "bamboo",
        "teamcity",
    ];

    for string in &analysis.embedded_strings {
        for indicator in &compromised_indicators {
            if string.contains(indicator) {
                let mut metadata_map = HashMap::new();
                metadata_map.insert(
                    "indicator".to_string(),
                    serde_json::Value::String(string.clone()),
                );

                anomalies.push(BuildAnomaly {
                    anomaly_type: BuildAnomalyType::CompromisedBuildEnvironment,
                    description: format!(
                        "Potential compromised build environment indicator: {}",
                        indicator
                    ),
                    severity: SeverityLevel::Low,
                    metadata: metadata_map,
                });
                break;
            }
        }
    }

    anomalies
}

fn analyze_dependency_issues(analysis: &BinaryAnalysis) -> Vec<DependencyIssue> {
    let mut issues = Vec::new();

    // Analyze linked libraries for known vulnerable versions
    for library in &analysis.linked_libraries {
        if let Some(issue) = check_library_vulnerabilities(library) {
            issues.push(issue);
        }
    }

    // Check for suspicious or malicious dependencies
    let suspicious_lib_patterns = [
        (
            "trojan",
            DependencyIssueType::Malicious,
            "Trojan-related library name",
        ),
        (
            "backdoor",
            DependencyIssueType::Malicious,
            "Backdoor-related library name",
        ),
        (
            "malware",
            DependencyIssueType::Malicious,
            "Malware-related library name",
        ),
        (
            "crack",
            DependencyIssueType::Suspicious,
            "Crack-related library",
        ),
        (
            "keygen",
            DependencyIssueType::Suspicious,
            "Key generator library",
        ),
        (
            "hack",
            DependencyIssueType::Suspicious,
            "Hack-related library",
        ),
    ];

    for library in &analysis.linked_libraries {
        let lower = library.to_lowercase();
        for (pattern, issue_type, description) in &suspicious_lib_patterns {
            if lower.contains(pattern) {
                issues.push(DependencyIssue {
                    dependency_name: library.clone(),
                    issue_type: issue_type.clone(),
                    severity: match issue_type {
                        DependencyIssueType::Malicious => SeverityLevel::Critical,
                        DependencyIssueType::Suspicious => SeverityLevel::High,
                        _ => SeverityLevel::Medium,
                    },
                    description: description.to_string(),
                    source_location: Some(analysis.file_name.clone()),
                });
                break;
            }
        }
    }

    // Check for outdated system libraries (basic heuristics)
    let system_libraries = [
        ("libc.so.6", "System C library"),
        ("libssl.so", "OpenSSL library"),
        ("libcrypto.so", "OpenSSL crypto library"),
        ("libcurl.so", "cURL library"),
        ("libxml2.so", "XML library"),
    ];

    for (lib_pattern, description) in &system_libraries {
        for library in &analysis.linked_libraries {
            if library.contains(lib_pattern) {
                // Very basic version checking - look for old version patterns
                if library.contains(".0.") || library.contains("1.0") {
                    issues.push(DependencyIssue {
                        dependency_name: library.clone(),
                        issue_type: DependencyIssueType::Outdated,
                        severity: SeverityLevel::Medium,
                        description: format!("Potentially outdated {}: {}", description, library),
                        source_location: Some(analysis.file_name.clone()),
                    });
                }
                break;
            }
        }
    }

    issues
}

fn check_library_vulnerabilities(library: &str) -> Option<DependencyIssue> {
    // Known vulnerable library versions (simplified examples)
    let vulnerable_libraries: HashMap<&str, (DependencyIssueType, SeverityLevel, &str)> =
        HashMap::from([
            (
                "libssl.so.1.0.0",
                (
                    DependencyIssueType::Vulnerable,
                    SeverityLevel::High,
                    "OpenSSL 1.0.0 has known vulnerabilities",
                ),
            ),
            (
                "libcurl.so.3",
                (
                    DependencyIssueType::Vulnerable,
                    SeverityLevel::Medium,
                    "Old cURL version may have vulnerabilities",
                ),
            ),
            (
                "libxml2.so.2.6",
                (
                    DependencyIssueType::Vulnerable,
                    SeverityLevel::Medium,
                    "Old libxml2 version",
                ),
            ),
        ]);

    for (vuln_lib, (issue_type, severity, description)) in &vulnerable_libraries {
        if library.contains(vuln_lib) {
            return Some(DependencyIssue {
                dependency_name: library.to_string(),
                issue_type: issue_type.clone(),
                severity: severity.clone(),
                description: description.to_string(),
                source_location: None,
            });
        }
    }

    None
}

// Helper functions

fn is_suspicious_url(url: &str) -> bool {
    let lower = url.to_lowercase();

    // Check for suspicious TLDs
    let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".bit", ".onion"];
    for tld in &suspicious_tlds {
        if lower.contains(tld) {
            return true;
        }
    }

    // Check for suspicious domain patterns
    let suspicious_patterns = [
        "bit.ly",
        "tinyurl",
        "goo.gl",
        "t.co", // URL shorteners
        "no-ip.org",
        "dyndns.org", // Dynamic DNS
        "ngrok.io",
        "localtunnel.me", // Tunneling services
    ];

    for pattern in &suspicious_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    // Check for IP addresses instead of domains
    if url.contains("://") {
        if let Some(domain_start) = url.find("://") {
            let domain_part = &url[domain_start + 3..];
            if let Some(path_start) = domain_part.find('/') {
                let domain = &domain_part[..path_start];
                if is_ip_address(domain) {
                    return true;
                }
            }
        }
    }

    false
}

fn is_likely_obfuscated_string(string: &str) -> bool {
    if string.len() < 10 {
        return false;
    }

    // Check for high percentage of non-alphanumeric characters
    let non_alphanum_count = string
        .chars()
        .filter(|c| !c.is_alphanumeric() && *c != ' ')
        .count();
    let non_alphanum_ratio = non_alphanum_count as f32 / string.len() as f32;

    if non_alphanum_ratio > 0.3 {
        return true;
    }

    // Check for repeated character patterns (common in obfuscation)
    let mut char_counts = HashMap::new();
    for c in string.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let max_char_count = char_counts.values().max().unwrap_or(&0);
    if *max_char_count as f32 / string.len() as f32 > 0.4 {
        return true;
    }

    false
}

fn is_ip_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    for part in parts {
        if part.parse::<u8>().is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_analysis() -> BinaryAnalysis {
        BinaryAnalysis {
            id: Uuid::new_v4(),
            file_name: "test.bin".to_string(),
            format: "elf".to_string(),
            architecture: "x86_64".to_string(),
            languages: vec!["C".to_string()],
            detected_symbols: vec!["CreateRemoteThread".to_string()],
            embedded_strings: vec![
                "31337".to_string(),
                "upx".to_string(),
                "http://malicious.example.com".to_string(),
            ],
            suspected_secrets: vec![],
            imports: vec!["WriteProcessMemory".to_string()],
            exports: vec![],
            hash_sha256: "test".to_string(),
            hash_blake3: None,
            size_bytes: 1024,
            linked_libraries: vec!["libssl.so.1.0.0".to_string()],
            static_linked: false,
            version_info: None,
            license_info: None,
            metadata: serde_json::json!({
                "compiler": "unknown_compiler"
            }),
            created_at: Utc::now(),
            sbom: None,
            binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
            entry_point: Some("0x401000".to_string()),
            code_sections: vec![],
        }
    }

    #[test]
    fn test_analyze_supply_chain_security() {
        let analysis = create_test_analysis();
        let result = analyze_supply_chain_security(&analysis);

        assert_eq!(result.file_path, "test.bin");
        assert!(!result.malicious_patterns.is_empty());
        assert!(!result.build_anomalies.is_empty());
        assert!(!result.dependency_issues.is_empty());
    }

    #[test]
    fn test_is_suspicious_url() {
        assert!(is_suspicious_url("http://malicious.tk/payload"));
        assert!(is_suspicious_url("https://192.168.1.1/backdoor"));
        assert!(!is_suspicious_url("https://google.com"));
    }

    #[test]
    fn test_is_likely_obfuscated_string() {
        assert!(is_likely_obfuscated_string("####@@@@!!!!%%%%"));
        assert!(is_likely_obfuscated_string("aaaaaaaaaaaaaaaaaa"));
        assert!(!is_likely_obfuscated_string("normal text string"));
    }
}
