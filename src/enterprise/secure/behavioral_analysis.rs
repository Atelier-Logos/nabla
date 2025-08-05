#![allow(dead_code)]
use crate::binary::BinaryAnalysis;
use crate::enterprise::secure::control_flow::ControlFlowGraph;
use crate::enterprise::types::{CodeLocation, ConfidenceLevel, SeverityLevel};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

pub fn analyze_behavioral_security(analysis: &BinaryAnalysis) -> BehavioralAnalysisResult {
    let start_time = Utc::now();

    let mut result = BehavioralAnalysisResult {
        analysis_id: Uuid::new_v4(),
        file_path: analysis.file_name.clone(),
        control_flow_anomalies: Vec::new(),
        network_patterns: Vec::new(),
        data_flow_issues: Vec::new(),
        analysis_duration_ms: 0,
    };

    // Build control flow graph for analysis
    let cfg = match ControlFlowGraph::build_cfg(analysis) {
        Ok(cfg) => cfg,
        Err(e) => {
            // Fallback to simplified analysis if CFG construction fails
            tracing::warn!("CFG construction failed: {}, using simplified analysis", e);
            return BehavioralAnalysisResult {
                analysis_id: Uuid::new_v4(),
                file_path: analysis.file_name.clone(),
                control_flow_anomalies: analyze_control_flow_anomalies_simple(analysis),
                network_patterns: analyze_network_patterns(analysis),
                data_flow_issues: analyze_data_flow_issues(analysis),
                analysis_duration_ms: (Utc::now() - start_time).num_milliseconds() as u64,
            };
        }
    };

    // Analyze control flow anomalies
    result.control_flow_anomalies = analyze_control_flow_anomalies(analysis, &cfg);

    // Analyze network communication patterns
    result.network_patterns = analyze_network_patterns(analysis);

    // Analyze data flow security issues
    result.data_flow_issues = analyze_data_flow_issues(analysis);

    let end_time = Utc::now();
    result.analysis_duration_ms = (end_time - start_time).num_milliseconds() as u64;

    result
}

fn analyze_control_flow_anomalies(
    analysis: &BinaryAnalysis,
    cfg: &ControlFlowGraph,
) -> Vec<ControlFlowAnomaly> {
    let mut anomalies = Vec::new();

    // Analyze loops for suspicious patterns
    for loop_info in &cfg.loops {
        match loop_info.loop_type {
            crate::enterprise::secure::control_flow::LoopType::Infinite => {
                anomalies.push(ControlFlowAnomaly {
                    anomaly_type: ControlFlowAnomalyType::SuspiciousLoop,
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: None,
                        binary_offset: None,
                    },
                    confidence: ConfidenceLevel::High,
                    description: format!(
                        "Infinite loop detected at address 0x{:x}",
                        loop_info.header
                    ),
                    call_graph_fragment: Some(vec![format!("0x{:x}", loop_info.header)]),
                });
            }
            crate::enterprise::secure::control_flow::LoopType::Irreducible => {
                anomalies.push(ControlFlowAnomaly {
                    anomaly_type: ControlFlowAnomalyType::HiddenBranch,
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: None,
                        binary_offset: None,
                    },
                    confidence: ConfidenceLevel::Medium,
                    description: "Irreducible control flow detected - possible obfuscation"
                        .to_string(),
                    call_graph_fragment: None,
                });
            }
            _ => {}
        }
    }

    // Analyze call graph for anomalies
    let call_graph = cfg.analyze_call_graph(analysis);

    // Check for suspicious recursion patterns
    for recursive_func in &call_graph.recursive_functions {
        anomalies.push(ControlFlowAnomaly {
            anomaly_type: ControlFlowAnomalyType::SuspiciousLoop,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: Some(recursive_func.clone()),
                binary_offset: None,
            },
            confidence: ConfidenceLevel::Medium,
            description: format!("Recursive function detected: {}", recursive_func),
            call_graph_fragment: Some(vec![recursive_func.clone()]),
        });
    }

    // Check for high cyclomatic complexity (possible obfuscation)
    for (func_name, summary) in &call_graph.function_summaries {
        if summary.cyclomatic_complexity > 20 {
            anomalies.push(ControlFlowAnomaly {
                anomaly_type: ControlFlowAnomalyType::HiddenBranch,
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(func_name.clone()),
                    binary_offset: None,
                },
                confidence: ConfidenceLevel::Medium,
                description: format!(
                    "High cyclomatic complexity ({}) in function {}",
                    summary.cyclomatic_complexity, func_name
                ),
                call_graph_fragment: Some(vec![func_name.clone()]),
            });
        }
    }

    // Add traditional pattern-based detection
    anomalies.extend(analyze_control_flow_anomalies_simple(analysis));

    anomalies
}

fn analyze_control_flow_anomalies_simple(analysis: &BinaryAnalysis) -> Vec<ControlFlowAnomaly> {
    let mut anomalies = Vec::new();

    // Detect anti-debugging patterns
    let anti_debug_functions = [
        "ptrace",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "GetTickCount",
        "timeGetTime",
        "rdtsc",
        "cpuid",
    ];

    for func in &anti_debug_functions {
        if analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
        {
            anomalies.push(ControlFlowAnomaly {
                anomaly_type: ControlFlowAnomalyType::AntiDebugPattern,
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(func.to_string()),
                    binary_offset: None,
                },
                confidence: ConfidenceLevel::High,
                description: format!("Anti-debugging function {} detected", func),
                call_graph_fragment: Some(vec![func.to_string()]),
            });
        }
    }

    // Detect suspicious control flow patterns in embedded strings
    for string in &analysis.embedded_strings {
        let lower = string.to_lowercase();

        // Look for obfuscation or packing indicators
        if lower.contains("upx") || lower.contains("packer") || lower.contains("packed") {
            anomalies.push(ControlFlowAnomaly {
                anomaly_type: ControlFlowAnomalyType::HiddenBranch,
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: None,
                    binary_offset: None,
                },
                confidence: ConfidenceLevel::Medium,
                description: "Potential code packing or obfuscation detected".to_string(),
                call_graph_fragment: None,
            });
        }

        // Look for VM detection strings
        if lower.contains("vmware")
            || lower.contains("virtualbox")
            || lower.contains("sandboxie")
            || lower.contains("wine")
        {
            anomalies.push(ControlFlowAnomaly {
                anomaly_type: ControlFlowAnomalyType::AntiDebugPattern,
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: None,
                    binary_offset: None,
                },
                confidence: ConfidenceLevel::Medium,
                description: "Virtual machine detection strings found".to_string(),
                call_graph_fragment: None,
            });
        }
    }

    // Detect unusual function call patterns
    let suspicious_patterns = detect_suspicious_call_patterns(analysis);
    anomalies.extend(suspicious_patterns);

    // Detect potential dead code indicators
    if analysis.detected_symbols.len() > analysis.imports.len() * 5 {
        anomalies.push(ControlFlowAnomaly {
            anomaly_type: ControlFlowAnomalyType::DeadCode,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            confidence: ConfidenceLevel::Low,
            description: "Large number of symbols relative to imports - potential dead code"
                .to_string(),
            call_graph_fragment: None,
        });
    }

    anomalies
}

fn detect_suspicious_call_patterns(analysis: &BinaryAnalysis) -> Vec<ControlFlowAnomaly> {
    let mut anomalies = Vec::new();

    // Pattern: Dynamic loading with execution
    let has_dlopen = analysis.imports.contains(&"dlopen".to_string());
    let has_dlsym = analysis.imports.contains(&"dlsym".to_string());
    let has_exec = analysis.imports.iter().any(|s| s.starts_with("exec"));

    if has_dlopen && has_dlsym && has_exec {
        anomalies.push(ControlFlowAnomaly {
            anomaly_type: ControlFlowAnomalyType::SuspiciousLoop,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            confidence: ConfidenceLevel::Medium,
            description: "Dynamic loading combined with execution - potential code injection"
                .to_string(),
            call_graph_fragment: Some(vec![
                "dlopen".to_string(),
                "dlsym".to_string(),
                "exec*".to_string(),
            ]),
        });
    }

    // Pattern: Memory manipulation with network functions
    let has_mmap = analysis.imports.contains(&"mmap".to_string());
    let has_mprotect = analysis.imports.contains(&"mprotect".to_string());
    let has_network = analysis.imports.iter().any(|s| {
        s.contains("socket") || s.contains("connect") || s.contains("recv") || s.contains("send")
    });

    if (has_mmap || has_mprotect) && has_network {
        anomalies.push(ControlFlowAnomaly {
            anomaly_type: ControlFlowAnomalyType::UnexpectedJump,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            confidence: ConfidenceLevel::Medium,
            description: "Memory manipulation combined with network functions - potential remote code execution".to_string(),
            call_graph_fragment: Some(vec!["mmap/mprotect".to_string(), "network_functions".to_string()]),
        });
    }

    anomalies
}

fn analyze_network_patterns(analysis: &BinaryAnalysis) -> Vec<NetworkPattern> {
    let mut patterns = Vec::new();

    // Detect network functions and suspicious patterns
    let network_functions = [
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "send",
        "recv",
        "sendto",
        "recvfrom",
        "getsockopt",
        "setsockopt",
        "select",
        "poll",
    ];

    let has_network = network_functions.iter().any(|&func| {
        analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
    });

    if has_network {
        // Look for suspicious network patterns in strings
        for string in &analysis.embedded_strings {
            let mut endpoints = Vec::new();
            let mut suspicious_indicators = Vec::new();

            // Check for IP addresses or domains
            if is_ip_address(string) || is_domain_name(string) {
                endpoints.push(string.clone());
            }

            // Check for suspicious ports
            if let Some(port) = extract_port_number(string) {
                if is_suspicious_port(port) {
                    patterns.push(NetworkPattern {
                        pattern_type: NetworkPatternType::SuspiciousPort,
                        endpoints: vec![string.clone()],
                        frequency: None,
                        suspicious_indicators: vec![format!("Suspicious port: {}", port)],
                    });
                }
            }

            // Check for DNS tunneling indicators
            if string.len() > 50
                && string.contains('.')
                && string.chars().filter(|&c| c == '.').count() > 5
            {
                patterns.push(NetworkPattern {
                    pattern_type: NetworkPatternType::DNSTunneling,
                    endpoints: vec![string.clone()],
                    frequency: None,
                    suspicious_indicators: vec!["Unusually long domain name".to_string()],
                });
            }

            // Check for base64 in network strings (potential C2)
            if is_likely_base64(string) && string.len() > 20 {
                suspicious_indicators.push("Base64-encoded data".to_string());
                patterns.push(NetworkPattern {
                    pattern_type: NetworkPatternType::CommandAndControl,
                    endpoints: vec![string.clone()],
                    frequency: None,
                    suspicious_indicators,
                });
            }
        }

        // General network usage pattern
        if !endpoints_found(&patterns) {
            patterns.push(NetworkPattern {
                pattern_type: NetworkPatternType::CommandAndControl,
                endpoints: vec!["Network functions detected".to_string()],
                frequency: None,
                suspicious_indicators: vec!["Generic network capability".to_string()],
            });
        }
    }

    // Check for potential beaconing patterns
    let has_timer = analysis
        .imports
        .iter()
        .any(|s| s.contains("sleep") || s.contains("timer") || s.contains("delay"));

    if has_network && has_timer {
        patterns.push(NetworkPattern {
            pattern_type: NetworkPatternType::Beaconing,
            endpoints: vec!["Timer + Network functions".to_string()],
            frequency: None,
            suspicious_indicators: vec!["Periodic network communication pattern".to_string()],
        });
    }

    patterns
}

fn analyze_data_flow_issues(analysis: &BinaryAnalysis) -> Vec<DataFlowIssue> {
    let mut issues = Vec::new();

    // Analyze input validation issues
    let input_functions = ["scanf", "gets", "fgets", "getchar", "recv", "recvfrom"];
    let output_functions = ["printf", "fprintf", "sprintf", "send", "sendto"];

    let has_input = input_functions.iter().any(|&func| {
        analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
    });

    let has_output = output_functions.iter().any(|&func| {
        analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
    });

    // Uncontrolled input without validation
    if has_input {
        for func in &input_functions {
            if analysis.imports.contains(&func.to_string())
                || analysis.detected_symbols.contains(&func.to_string())
            {
                let severity = match *func {
                    "gets" => SeverityLevel::Critical,
                    "scanf" => SeverityLevel::High,
                    _ => SeverityLevel::Medium,
                };

                issues.push(DataFlowIssue {
                    issue_type: DataFlowIssueType::UncontrolledInput,
                    source: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some(func.to_string()),
                        binary_offset: None,
                    },
                    sink: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some("unknown".to_string()),
                        binary_offset: None,
                    },
                    severity,
                    data_path: vec![func.to_string()],
                });
            }
        }
    }

    // Potential data leakage through output functions
    if has_input && has_output {
        issues.push(DataFlowIssue {
            issue_type: DataFlowIssueType::DataLeakage,
            source: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: Some("input_functions".to_string()),
                binary_offset: None,
            },
            sink: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: Some("output_functions".to_string()),
                binary_offset: None,
            },
            severity: SeverityLevel::Medium,
            data_path: vec![
                "input".to_string(),
                "processing".to_string(),
                "output".to_string(),
            ],
        });
    }

    // Privilege escalation risks
    let privilege_functions = ["setuid", "setgid", "seteuid", "setegid", "sudo", "su"];
    for func in &privilege_functions {
        if analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
        {
            issues.push(DataFlowIssue {
                issue_type: DataFlowIssueType::PrivilegeEscalation,
                source: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some("user_input".to_string()),
                    binary_offset: None,
                },
                sink: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(func.to_string()),
                    binary_offset: None,
                },
                severity: SeverityLevel::High,
                data_path: vec!["user_input".to_string(), func.to_string()],
            });
        }
    }

    // Unsanitized output to system functions
    let system_functions = ["system", "exec", "popen"];
    if has_input {
        for func in &system_functions {
            if analysis.imports.contains(&func.to_string())
                || analysis.detected_symbols.contains(&func.to_string())
            {
                issues.push(DataFlowIssue {
                    issue_type: DataFlowIssueType::UnsanitizedOutput,
                    source: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some("user_input".to_string()),
                        binary_offset: None,
                    },
                    sink: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some(func.to_string()),
                        binary_offset: None,
                    },
                    severity: SeverityLevel::Critical,
                    data_path: vec!["user_input".to_string(), func.to_string()],
                });
            }
        }
    }

    issues
}

// Helper functions for pattern detection

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

fn is_domain_name(s: &str) -> bool {
    s.contains('.')
        && s.len() > 4
        && s.len() < 255
        && !s.contains(' ')
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
}

fn extract_port_number(s: &str) -> Option<u16> {
    // Look for :port pattern
    if let Some(colon_pos) = s.rfind(':') {
        if let Ok(port) = s[colon_pos + 1..].parse::<u16>() {
            return Some(port);
        }
    }

    // Check if the entire string is a port number
    if let Ok(port) = s.parse::<u16>() {
        if port > 0 {
            return Some(port);
        }
    }

    None
}

fn is_suspicious_port(port: u16) -> bool {
    // Common malware/hacking ports
    matches!(
        port,
        31337 | 12345 | 54321 | 9999 | // Common backdoor ports
        4444 | 5555 | 7777 | 8888 |    // Common reverse shell ports
        6666 | 666 |                   // Suspicious numbers
        1234 | 4321 |                  // Simple patterns
        31338 | 31339 // Elite variations
    )
}

fn is_likely_base64(s: &str) -> bool {
    if s.len() < 4 || s.len() % 4 != 0 {
        return false;
    }

    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && s.chars().filter(|&c| c == '=').count() <= 2
}

fn endpoints_found(patterns: &[NetworkPattern]) -> bool {
    patterns
        .iter()
        .any(|p| !p.endpoints.is_empty() && !p.endpoints.iter().all(|e| e.contains("functions")))
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
            detected_symbols: vec!["socket".to_string(), "ptrace".to_string()],
            embedded_strings: vec!["192.168.1.1".to_string(), "vmware".to_string()],
            suspected_secrets: vec![],
            imports: vec![
                "connect".to_string(),
                "recv".to_string(),
                "gets".to_string(),
            ],
            exports: vec![],
            hash_sha256: "test".to_string(),
            hash_blake3: None,
            size_bytes: 1024,
            linked_libraries: vec!["libc.so.6".to_string()],
            static_linked: false,
            version_info: None,
            license_info: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            sbom: None,
            binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
            entry_point: Some("0x401000".to_string()),
            code_sections: vec![],
        }
    }

    #[test]
    fn test_analyze_behavioral_security() {
        let analysis = create_test_analysis();
        let result = analyze_behavioral_security(&analysis);

        assert_eq!(result.file_path, "test.bin");
        assert!(!result.control_flow_anomalies.is_empty());
        assert!(!result.network_patterns.is_empty());
        assert!(!result.data_flow_issues.is_empty());
    }

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("127.0.0.1"));
        assert!(!is_ip_address("256.1.1.1"));
        assert!(!is_ip_address("not.an.ip"));
    }

    #[test]
    fn test_is_suspicious_port() {
        assert!(is_suspicious_port(31337));
        assert!(is_suspicious_port(12345));
        assert!(!is_suspicious_port(80));
        assert!(!is_suspicious_port(443));
    }
}
