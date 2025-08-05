#![allow(dead_code)]
use crate::binary::BinaryAnalysis;
use crate::enterprise::types::{CodeLocation, SeverityLevel};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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

pub fn analyze_static_security(analysis: &BinaryAnalysis) -> StaticAnalysisResult {
    let start_time = Utc::now();

    let mut result = StaticAnalysisResult {
        analysis_id: Uuid::new_v4(),
        file_path: analysis.file_name.clone(),
        unsafe_functions: Vec::new(),
        memory_issues: Vec::new(),
        system_calls: Vec::new(),
        hardening_issues: Vec::new(),
        analysis_duration_ms: 0,
    };

    // Analyze unsafe functions from imports and symbols
    result.unsafe_functions = analyze_unsafe_functions(analysis);

    // Analyze memory-related security issues
    result.memory_issues = analyze_memory_issues(analysis);

    // Analyze dangerous system calls
    result.system_calls = analyze_system_calls(analysis);

    // Analyze hardening features
    result.hardening_issues = analyze_hardening_features(analysis);

    let end_time = Utc::now();
    result.analysis_duration_ms = (end_time - start_time).num_milliseconds() as u64;

    result
}

fn analyze_unsafe_functions(analysis: &BinaryAnalysis) -> Vec<UnsafeFunctionFinding> {
    let mut findings = Vec::new();

    // Define dangerous C functions and their safer alternatives
    let unsafe_functions: HashMap<&str, (SeverityLevel, &str, Vec<&str>)> = HashMap::from([
        (
            "strcpy",
            (
                SeverityLevel::High,
                "Buffer overflow risk - no bounds checking",
                vec!["strncpy", "strlcpy", "strcpy_s"],
            ),
        ),
        (
            "strcat",
            (
                SeverityLevel::High,
                "Buffer overflow risk - no bounds checking",
                vec!["strncat", "strlcat", "strcat_s"],
            ),
        ),
        (
            "sprintf",
            (
                SeverityLevel::High,
                "Buffer overflow risk - no size limit",
                vec!["snprintf", "sprintf_s"],
            ),
        ),
        (
            "vsprintf",
            (
                SeverityLevel::High,
                "Buffer overflow risk - no size limit",
                vec!["vsnprintf", "vsprintf_s"],
            ),
        ),
        (
            "gets",
            (
                SeverityLevel::Critical,
                "Always vulnerable to buffer overflow",
                vec!["fgets", "getline"],
            ),
        ),
        (
            "scanf",
            (
                SeverityLevel::High,
                "Format string and buffer overflow risks",
                vec!["fgets with parsing", "scanf_s"],
            ),
        ),
        (
            "sscanf",
            (
                SeverityLevel::Medium,
                "Format string risks",
                vec!["sscanf_s", "manual parsing"],
            ),
        ),
        (
            "memcpy",
            (
                SeverityLevel::Medium,
                "No overlap checking",
                vec!["memmove", "memcpy_s"],
            ),
        ),
        (
            "strncpy",
            (
                SeverityLevel::Medium,
                "May not null-terminate",
                vec!["strlcpy", "strncpy_s"],
            ),
        ),
        (
            "strncat",
            (
                SeverityLevel::Medium,
                "Complex length calculation",
                vec!["strlcat", "strncat_s"],
            ),
        ),
        (
            "realpath",
            (
                SeverityLevel::Medium,
                "Path traversal if misused",
                vec!["realpath with buffer size check"],
            ),
        ),
        (
            "mktemp",
            (
                SeverityLevel::High,
                "Race condition vulnerability",
                vec!["mkstemp", "mkdtemp"],
            ),
        ),
        (
            "tmpnam",
            (
                SeverityLevel::High,
                "Race condition vulnerability",
                vec!["tmpfile", "mkstemp"],
            ),
        ),
        (
            "alloca",
            (
                SeverityLevel::Medium,
                "Stack overflow risk",
                vec!["malloc with proper cleanup"],
            ),
        ),
        (
            "setuid",
            (
                SeverityLevel::High,
                "Privilege escalation risk",
                vec!["proper privilege dropping sequence"],
            ),
        ),
        (
            "setgid",
            (
                SeverityLevel::High,
                "Privilege escalation risk",
                vec!["proper privilege dropping sequence"],
            ),
        ),
        (
            "system",
            (
                SeverityLevel::Critical,
                "Command injection vulnerability",
                vec!["execve", "posix_spawn"],
            ),
        ),
        (
            "popen",
            (
                SeverityLevel::High,
                "Command injection risk",
                vec!["fork + exec pattern"],
            ),
        ),
        (
            "eval",
            (
                SeverityLevel::Critical,
                "Code injection vulnerability",
                vec!["safe parsing alternatives"],
            ),
        ),
        (
            "exec",
            (
                SeverityLevel::High,
                "Command injection if input not sanitized",
                vec!["execve with argument validation"],
            ),
        ),
    ]);

    // Check imports for unsafe functions
    for import in &analysis.imports {
        if let Some((severity, description, alternatives)) = unsafe_functions.get(import.as_str()) {
            findings.push(UnsafeFunctionFinding {
                function_name: import.clone(),
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(import.clone()),
                    binary_offset: None,
                },
                risk_level: severity.clone(),
                description: description.to_string(),
                alternatives: alternatives.iter().map(|s| s.to_string()).collect(),
            });
        }
    }

    // Check detected symbols for unsafe functions
    for symbol in &analysis.detected_symbols {
        if let Some((severity, description, alternatives)) = unsafe_functions.get(symbol.as_str()) {
            // Avoid duplicates from imports
            if !findings.iter().any(|f| f.function_name == *symbol) {
                findings.push(UnsafeFunctionFinding {
                    function_name: symbol.clone(),
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some(symbol.clone()),
                        binary_offset: None,
                    },
                    risk_level: severity.clone(),
                    description: description.to_string(),
                    alternatives: alternatives.iter().map(|s| s.to_string()).collect(),
                });
            }
        }
    }

    findings
}

fn analyze_memory_issues(analysis: &BinaryAnalysis) -> Vec<MemoryIssueFinding> {
    let mut findings = Vec::new();

    // Check for potential memory management issues based on function usage patterns
    let has_malloc = analysis.imports.iter().any(|s| s == "malloc")
        || analysis.detected_symbols.iter().any(|s| s == "malloc");
    let has_free = analysis.imports.iter().any(|s| s == "free")
        || analysis.detected_symbols.iter().any(|s| s == "free");
    let has_calloc = analysis.imports.iter().any(|s| s == "calloc")
        || analysis.detected_symbols.iter().any(|s| s == "calloc");

    // Check for memory allocation without corresponding deallocation
    if (has_malloc || has_calloc) && !has_free {
        findings.push(MemoryIssueFinding {
            issue_type: MemoryIssueType::MemoryLeak,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: Some("malloc".to_string()),
                binary_offset: None,
            },
            severity: SeverityLevel::Medium,
            description:
                "Memory allocation detected without corresponding free() - potential memory leak"
                    .to_string(),
            vulnerable_code: None,
        });
    }

    // Check for potential integer overflow in size calculations
    let size_related_functions = ["malloc", "calloc", "realloc", "memcpy", "memset"];
    for func in &size_related_functions {
        if analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
        {
            findings.push(MemoryIssueFinding {
                issue_type: MemoryIssueType::IntegerOverflow,
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(func.to_string()),
                    binary_offset: None,
                },
                severity: SeverityLevel::Medium,
                description: format!(
                    "Function {} may be vulnerable to integer overflow in size calculations",
                    func
                ),
                vulnerable_code: None,
            });
        }
    }

    // Check for unbounded memory operations
    let unbounded_functions = [
        ("strcpy", MemoryIssueType::UnboundedWrite),
        ("strcat", MemoryIssueType::UnboundedWrite),
        ("sprintf", MemoryIssueType::UnboundedWrite),
        ("gets", MemoryIssueType::UnboundedRead),
    ];

    for (func, issue_type) in &unbounded_functions {
        if analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
        {
            findings.push(MemoryIssueFinding {
                issue_type: issue_type.clone(),
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(func.to_string()),
                    binary_offset: None,
                },
                severity: SeverityLevel::High,
                description: format!("Function {} performs unbounded memory operations", func),
                vulnerable_code: Some(format!("{}(...)", func)),
            });
        }
    }

    findings
}

fn analyze_system_calls(analysis: &BinaryAnalysis) -> Vec<SystemCallFinding> {
    let mut findings = Vec::new();

    // Define dangerous system calls and their risk levels
    let dangerous_syscalls: HashMap<&str, (SeverityLevel, &str, Option<&str>)> = HashMap::from([
        (
            "system",
            (
                SeverityLevel::Critical,
                "Command injection vulnerability",
                Some("Use execve() with proper argument validation"),
            ),
        ),
        (
            "exec",
            (
                SeverityLevel::High,
                "Potential command injection",
                Some("Validate all arguments and use execve()"),
            ),
        ),
        (
            "execl",
            (
                SeverityLevel::High,
                "Potential command injection",
                Some("Validate all arguments"),
            ),
        ),
        (
            "execlp",
            (
                SeverityLevel::High,
                "Potential command injection",
                Some("Validate all arguments and avoid PATH dependency"),
            ),
        ),
        (
            "execle",
            (
                SeverityLevel::High,
                "Potential command injection",
                Some("Validate all arguments"),
            ),
        ),
        (
            "execv",
            (
                SeverityLevel::High,
                "Potential command injection",
                Some("Validate all arguments"),
            ),
        ),
        (
            "execvp",
            (
                SeverityLevel::High,
                "Potential command injection",
                Some("Validate all arguments and avoid PATH dependency"),
            ),
        ),
        (
            "execve",
            (
                SeverityLevel::Medium,
                "Safe if arguments are validated",
                Some("Ensure all arguments are properly validated"),
            ),
        ),
        (
            "popen",
            (
                SeverityLevel::High,
                "Command injection risk",
                Some("Use fork() + execve() pattern instead"),
            ),
        ),
        (
            "fork",
            (
                SeverityLevel::Medium,
                "Resource exhaustion risk",
                Some("Implement proper process limiting"),
            ),
        ),
        (
            "setuid",
            (
                SeverityLevel::High,
                "Privilege escalation risk",
                Some("Use proper privilege dropping sequence"),
            ),
        ),
        (
            "setgid",
            (
                SeverityLevel::High,
                "Privilege escalation risk",
                Some("Use proper privilege dropping sequence"),
            ),
        ),
        (
            "seteuid",
            (
                SeverityLevel::High,
                "Privilege escalation risk",
                Some("Use proper privilege dropping sequence"),
            ),
        ),
        (
            "setegid",
            (
                SeverityLevel::High,
                "Privilege escalation risk",
                Some("Use proper privilege dropping sequence"),
            ),
        ),
        (
            "chroot",
            (
                SeverityLevel::Medium,
                "Incomplete sandboxing",
                Some("Combine with proper privilege dropping"),
            ),
        ),
        (
            "ptrace",
            (
                SeverityLevel::Medium,
                "Debugging/injection risk",
                Some("Restrict usage and validate target processes"),
            ),
        ),
        (
            "mmap",
            (
                SeverityLevel::Low,
                "Memory mapping risks",
                Some("Use appropriate flags and validate addresses"),
            ),
        ),
        (
            "mprotect",
            (
                SeverityLevel::Medium,
                "Memory protection bypass",
                Some("Avoid making pages writable and executable"),
            ),
        ),
        (
            "dlopen",
            (
                SeverityLevel::Medium,
                "Dynamic loading risk",
                Some("Validate library paths and use RTLD_NOW"),
            ),
        ),
        (
            "dlsym",
            (
                SeverityLevel::Medium,
                "Symbol resolution risk",
                Some("Validate symbol names"),
            ),
        ),
        (
            "signal",
            (
                SeverityLevel::Low,
                "Signal handling race conditions",
                Some("Use sigaction() instead"),
            ),
        ),
        (
            "alarm",
            (
                SeverityLevel::Low,
                "Signal race conditions",
                Some("Use timer_create() for better control"),
            ),
        ),
    ]);

    // Check imports and symbols for dangerous system calls
    for item in analysis
        .imports
        .iter()
        .chain(analysis.detected_symbols.iter())
    {
        if let Some((severity, reason, mitigation)) = dangerous_syscalls.get(item.as_str()) {
            findings.push(SystemCallFinding {
                syscall_name: item.clone(),
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(item.clone()),
                    binary_offset: None,
                },
                danger_level: severity.clone(),
                reason: reason.to_string(),
                mitigation: mitigation.map(|s| s.to_string()),
            });
        }
    }

    findings
}

fn analyze_hardening_features(analysis: &BinaryAnalysis) -> Vec<HardeningFinding> {
    let mut findings = Vec::new();

    // Check for stack canaries (GCC stack protection)
    let has_stack_protection = analysis
        .detected_symbols
        .iter()
        .any(|s| s.contains("__stack_chk_fail") || s.contains("__stack_chk_guard"))
        || analysis
            .imports
            .iter()
            .any(|s| s.contains("__stack_chk_fail") || s.contains("__stack_chk_guard"));

    findings.push(HardeningFinding {
        hardening_feature: "Stack Canaries".to_string(),
        status: if has_stack_protection {
            HardeningStatus::Present
        } else {
            HardeningStatus::Missing
        },
        recommendation: if has_stack_protection {
            "Stack canaries are present - good security practice".to_string()
        } else {
            "Enable stack protection (-fstack-protector-strong or -fstack-protector-all)"
                .to_string()
        },
        impact: SeverityLevel::High,
    });

    // Check for position independent executable (PIE) indicators
    let metadata_str = analysis.metadata.to_string().to_lowercase();
    let has_pie = metadata_str.contains("pie") || metadata_str.contains("position independent");

    findings.push(HardeningFinding {
        hardening_feature: "Position Independent Executable (PIE)".to_string(),
        status: if has_pie {
            HardeningStatus::Present
        } else {
            HardeningStatus::Missing
        },
        recommendation: if has_pie {
            "PIE is enabled - provides ASLR benefits".to_string()
        } else {
            "Enable PIE compilation (-fPIE -pie) for ASLR protection".to_string()
        },
        impact: SeverityLevel::Medium,
    });

    // Check for RELRO (Read-Only Relocations)
    let has_relro = analysis.detected_symbols.iter().any(|s| {
        s.contains("__libc_start_main")
            && analysis.linked_libraries.iter().any(|l| l.contains("libc"))
    });

    findings.push(HardeningFinding {
        hardening_feature: "RELRO (Read-Only Relocations)".to_string(),
        status: if has_relro {
            HardeningStatus::Present
        } else {
            HardeningStatus::Missing
        },
        recommendation: if has_relro {
            "RELRO appears to be enabled - protects GOT from overwrites".to_string()
        } else {
            "Enable full RELRO (-Wl,-z,relro,-z,now) for GOT protection".to_string()
        },
        impact: SeverityLevel::Medium,
    });

    // Check for NX/DEP (Data Execution Prevention)
    let is_executable_stack = analysis
        .detected_symbols
        .iter()
        .any(|s| s.contains("execstack"));

    findings.push(HardeningFinding {
        hardening_feature: "NX/DEP (Data Execution Prevention)".to_string(),
        status: if is_executable_stack {
            HardeningStatus::Weak
        } else {
            HardeningStatus::Present
        },
        recommendation: if is_executable_stack {
            "Executable stack detected - disable with -Wl,-z,noexecstack".to_string()
        } else {
            "NX/DEP appears to be enabled - stack is non-executable".to_string()
        },
        impact: SeverityLevel::High,
    });

    // Check for format string protections
    let has_fortify = analysis.detected_symbols.iter().any(|s| {
        s.contains("__printf_chk")
            || s.contains("__sprintf_chk")
            || s.contains("__snprintf_chk")
            || s.contains("__vprintf_chk")
    });

    findings.push(HardeningFinding {
        hardening_feature: "FORTIFY_SOURCE".to_string(),
        status: if has_fortify {
            HardeningStatus::Present
        } else {
            HardeningStatus::Missing
        },
        recommendation: if has_fortify {
            "FORTIFY_SOURCE is enabled - provides runtime buffer overflow detection".to_string()
        } else {
            "Enable FORTIFY_SOURCE (-D_FORTIFY_SOURCE=2) for buffer overflow protection".to_string()
        },
        impact: SeverityLevel::Medium,
    });

    // Check for static linking (can be a hardening concern)
    findings.push(HardeningFinding {
        hardening_feature: "Dynamic Linking".to_string(),
        status: if analysis.static_linked {
            HardeningStatus::Missing
        } else {
            HardeningStatus::Present
        },
        recommendation: if analysis.static_linked {
            "Binary is statically linked - consider dynamic linking for security updates"
                .to_string()
        } else {
            "Binary uses dynamic linking - enables library security updates".to_string()
        },
        impact: SeverityLevel::Low,
    });

    findings
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
            detected_symbols: vec!["malloc".to_string(), "strcpy".to_string()],
            embedded_strings: vec![],
            suspected_secrets: vec![],
            imports: vec!["system".to_string(), "gets".to_string()],
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
            binary_data: None,
            entry_point: None,
            code_sections: Vec::new(),
        }
    }

    #[test]
    fn test_analyze_unsafe_functions() {
        let analysis = create_test_analysis();
        let findings = analyze_unsafe_functions(&analysis);

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.function_name == "strcpy"));
        assert!(findings.iter().any(|f| f.function_name == "gets"));
        assert!(findings.iter().any(|f| f.function_name == "system"));
    }

    #[test]
    fn test_analyze_static_security() {
        let analysis = create_test_analysis();
        let result = analyze_static_security(&analysis);

        assert_eq!(result.file_path, "test.bin");
        assert!(!result.unsafe_functions.is_empty());
        assert!(!result.system_calls.is_empty());
        assert!(!result.hardening_issues.is_empty());
    }
}
