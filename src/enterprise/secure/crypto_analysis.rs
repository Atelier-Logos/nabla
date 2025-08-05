#![allow(dead_code)]
use crate::binary::BinaryAnalysis;
use crate::enterprise::types::{CodeLocation, SeverityLevel};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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

pub fn analyze_crypto_security(analysis: &BinaryAnalysis) -> CryptoAnalysisResult {
    let start_time = Utc::now();

    let mut result = CryptoAnalysisResult {
        analysis_id: Uuid::new_v4(),
        file_path: analysis.file_name.clone(),
        key_issues: Vec::new(),
        algorithm_issues: Vec::new(),
        implementation_issues: Vec::new(),
        analysis_duration_ms: 0,
    };

    // Analyze key management issues
    result.key_issues = analyze_key_issues(analysis);

    // Analyze cryptographic algorithm usage
    result.algorithm_issues = analyze_algorithm_issues(analysis);

    // Analyze implementation-specific crypto issues
    result.implementation_issues = analyze_implementation_issues(analysis);

    let end_time = Utc::now();
    result.analysis_duration_ms = (end_time - start_time).num_milliseconds() as u64;

    result
}

fn analyze_key_issues(analysis: &BinaryAnalysis) -> Vec<KeyIssue> {
    let mut issues = Vec::new();

    // Check for hardcoded keys in embedded strings
    for string in &analysis.embedded_strings {
        if let Some(key_issue) = detect_hardcoded_key(string, &analysis.file_name) {
            issues.push(key_issue);
        }
    }

    // Check for weak key generation functions
    let weak_key_gen_functions = [
        (
            "rand",
            "Use cryptographically secure random number generators like /dev/urandom or CryptGenRandom",
        ),
        (
            "random",
            "Use cryptographically secure random number generators",
        ),
        ("srand", "Predictable seed - use secure random generators"),
        (
            "time",
            "Time-based seeds are predictable - use secure entropy sources",
        ),
    ];

    for (func, recommendation) in &weak_key_gen_functions {
        if analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
        {
            issues.push(KeyIssue {
                issue_type: KeyIssueType::InsecureKeyGeneration,
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: Some(func.to_string()),
                    binary_offset: None,
                },
                severity: SeverityLevel::High,
                key_material: None,
                recommendation: recommendation.to_string(),
            });
        }
    }

    // Check for key storage issues
    let key_storage_functions = ["fopen", "fwrite", "fprintf"];
    let has_file_ops = key_storage_functions.iter().any(|&func| {
        analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
    });

    if has_file_ops && has_crypto_context(analysis) {
        issues.push(KeyIssue {
            issue_type: KeyIssueType::KeyInPlaintext,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::Medium,
            key_material: None,
            recommendation: "Ensure cryptographic keys are encrypted before storage".to_string(),
        });
    }

    issues
}

fn detect_hardcoded_key(string: &str, file_path: &str) -> Option<KeyIssue> {
    // Check for various key patterns

    // RSA private key headers
    if string.contains("-----BEGIN RSA PRIVATE KEY-----")
        || string.contains("-----BEGIN PRIVATE KEY-----")
    {
        return Some(KeyIssue {
            issue_type: KeyIssueType::HardcodedKey,
            location: CodeLocation {
                file_path: file_path.to_string(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::Critical,
            key_material: Some(format!(
                "RSA_KEY_{}...",
                &string.chars().take(8).collect::<String>()
            )),
            recommendation: "Remove hardcoded private keys - use secure key management".to_string(),
        });
    }

    // Certificate patterns
    if string.contains("-----BEGIN CERTIFICATE-----") {
        return Some(KeyIssue {
            issue_type: KeyIssueType::HardcodedKey,
            location: CodeLocation {
                file_path: file_path.to_string(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::Medium,
            key_material: Some("CERTIFICATE_DATA".to_string()),
            recommendation: "Certificates should be loaded from secure storage".to_string(),
        });
    }

    // Base64 encoded keys (common pattern)
    if is_likely_encoded_key(string) {
        return Some(KeyIssue {
            issue_type: KeyIssueType::HardcodedKey,
            location: CodeLocation {
                file_path: file_path.to_string(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::High,
            key_material: Some(format!(
                "ENCODED_KEY_{}...",
                &string.chars().take(8).collect::<String>()
            )),
            recommendation: "Suspected encoded key material should not be hardcoded".to_string(),
        });
    }

    // Hexadecimal keys (32+ hex chars could be a key)
    if is_hex_key_pattern(string) {
        return Some(KeyIssue {
            issue_type: KeyIssueType::HardcodedKey,
            location: CodeLocation {
                file_path: file_path.to_string(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::High,
            key_material: Some(format!(
                "HEX_KEY_{}...",
                &string.chars().take(8).collect::<String>()
            )),
            recommendation: "Suspected hexadecimal key should not be hardcoded".to_string(),
        });
    }

    // API keys and tokens patterns
    if is_api_key_pattern(string) {
        return Some(KeyIssue {
            issue_type: KeyIssueType::HardcodedKey,
            location: CodeLocation {
                file_path: file_path.to_string(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::High,
            key_material: Some("API_KEY_[REDACTED]".to_string()),
            recommendation:
                "API keys should be loaded from environment variables or secure configuration"
                    .to_string(),
        });
    }

    None
}

fn analyze_algorithm_issues(analysis: &BinaryAnalysis) -> Vec<AlgorithmIssue> {
    let mut issues = Vec::new();

    // Define deprecated/weak algorithms
    let weak_algorithms: HashMap<&str, (AlgorithmIssueType, SeverityLevel, Option<&str>)> =
        HashMap::from([
            (
                "md5",
                (
                    AlgorithmIssueType::Broken,
                    SeverityLevel::High,
                    Some("SHA-256 or SHA-3"),
                ),
            ),
            (
                "sha1",
                (
                    AlgorithmIssueType::Weak,
                    SeverityLevel::Medium,
                    Some("SHA-256 or SHA-3"),
                ),
            ),
            (
                "des",
                (
                    AlgorithmIssueType::Broken,
                    SeverityLevel::Critical,
                    Some("AES"),
                ),
            ),
            (
                "3des",
                (
                    AlgorithmIssueType::Deprecated,
                    SeverityLevel::Medium,
                    Some("AES"),
                ),
            ),
            (
                "rc4",
                (
                    AlgorithmIssueType::Broken,
                    SeverityLevel::Critical,
                    Some("AES or ChaCha20"),
                ),
            ),
            (
                "rc2",
                (AlgorithmIssueType::Broken, SeverityLevel::High, Some("AES")),
            ),
            (
                "blowfish",
                (AlgorithmIssueType::Weak, SeverityLevel::Medium, Some("AES")),
            ),
            (
                "md4",
                (
                    AlgorithmIssueType::Broken,
                    SeverityLevel::Critical,
                    Some("SHA-256 or SHA-3"),
                ),
            ),
            (
                "md2",
                (
                    AlgorithmIssueType::Broken,
                    SeverityLevel::Critical,
                    Some("SHA-256 or SHA-3"),
                ),
            ),
        ]);

    // Check for weak algorithms in strings and function names
    for string in analysis
        .embedded_strings
        .iter()
        .chain(analysis.imports.iter())
        .chain(analysis.detected_symbols.iter())
    {
        let lower = string.to_lowercase();

        for (algorithm, (issue_type, severity, replacement)) in &weak_algorithms {
            if lower.contains(algorithm) || lower.contains(&algorithm.to_uppercase()) {
                issues.push(AlgorithmIssue {
                    algorithm_name: algorithm.to_uppercase(),
                    issue_type: issue_type.clone(),
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: if analysis.imports.contains(string)
                            || analysis.detected_symbols.contains(string)
                        {
                            Some(string.clone())
                        } else {
                            None
                        },
                        binary_offset: None,
                    },
                    severity: severity.clone(),
                    replacement_suggestion: replacement.map(|s| s.to_string()),
                });
            }
        }
    }

    // Check for crypto libraries and their algorithm usage
    for lib in &analysis.linked_libraries {
        let lower = lib.to_lowercase();

        // OpenSSL version analysis
        if lower.contains("openssl") || lower.contains("libssl") || lower.contains("libcrypto") {
            // Check for old OpenSSL versions (very basic detection)
            if lower.contains("0.9") || lower.contains("1.0.0") {
                issues.push(AlgorithmIssue {
                    algorithm_name: "OpenSSL".to_string(),
                    issue_type: AlgorithmIssueType::Deprecated,
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: None,
                        binary_offset: None,
                    },
                    severity: SeverityLevel::High,
                    replacement_suggestion: Some("Update to OpenSSL 1.1.1+ or 3.x".to_string()),
                });
            }
        }
    }

    // Check for RSA key size issues (basic heuristic)
    if analysis
        .embedded_strings
        .iter()
        .any(|s| s.contains("1024") && s.to_lowercase().contains("rsa"))
    {
        issues.push(AlgorithmIssue {
            algorithm_name: "RSA-1024".to_string(),
            issue_type: AlgorithmIssueType::Weak,
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::Medium,
            replacement_suggestion: Some("Use RSA-2048 or higher, or consider ECDSA".to_string()),
        });
    }

    issues
}

fn analyze_implementation_issues(analysis: &BinaryAnalysis) -> Vec<CryptoImplementationIssue> {
    let mut issues = Vec::new();

    // Check for ECB mode usage (Electronic Codebook - insecure)
    if analysis
        .embedded_strings
        .iter()
        .any(|s| s.to_lowercase().contains("ecb"))
    {
        issues.push(CryptoImplementationIssue {
            issue_description:
                "ECB (Electronic Codebook) mode detected - insecure block cipher mode".to_string(),
            location: CodeLocation {
                file_path: analysis.file_name.clone(),
                line_number: None,
                column_number: None,
                function_name: None,
                binary_offset: None,
            },
            severity: SeverityLevel::High,
            cwe_id: Some("CWE-327".to_string()),
        });
    }

    // Check for hardcoded IV/salt patterns
    let iv_salt_indicators = ["iv", "salt", "nonce", "vector"];
    for indicator in &iv_salt_indicators {
        if analysis.embedded_strings.iter().any(|s| {
            let lower = s.to_lowercase();
            lower.contains(indicator) && (s.len() > 16 && s.chars().all(|c| c.is_ascii_hexdigit()))
        }) {
            issues.push(CryptoImplementationIssue {
                issue_description: format!("Potential hardcoded {} detected", indicator)
                    .to_string(),
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: None,
                    binary_offset: None,
                },
                severity: SeverityLevel::Medium,
                cwe_id: Some("CWE-330".to_string()),
            });
        }
    }

    // Check for insecure random number generation in crypto context
    if has_crypto_context(analysis) {
        let insecure_rng = ["rand", "random", "srand"];
        for rng_func in &insecure_rng {
            if analysis.imports.contains(&rng_func.to_string())
                || analysis.detected_symbols.contains(&rng_func.to_string())
            {
                issues.push(CryptoImplementationIssue {
                    issue_description: format!(
                        "Insecure RNG ({}) used in cryptographic context",
                        rng_func
                    ),
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some(rng_func.to_string()),
                        binary_offset: None,
                    },
                    severity: SeverityLevel::High,
                    cwe_id: Some("CWE-338".to_string()),
                });
            }
        }
    }

    // Check for timing attack vulnerabilities
    let timing_vuln_functions = ["strcmp", "memcmp"];
    let has_crypto_functions = analysis
        .imports
        .iter()
        .chain(analysis.detected_symbols.iter())
        .any(|s| {
            s.to_lowercase().contains("crypto")
                || s.to_lowercase().contains("hash")
                || s.to_lowercase().contains("cipher")
        });

    if has_crypto_functions {
        for func in &timing_vuln_functions {
            if analysis.imports.contains(&func.to_string())
                || analysis.detected_symbols.contains(&func.to_string())
            {
                issues.push(CryptoImplementationIssue {
                    issue_description: format!(
                        "Timing attack vulnerability: {} used in crypto context",
                        func
                    ),
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some(func.to_string()),
                        binary_offset: None,
                    },
                    severity: SeverityLevel::Medium,
                    cwe_id: Some("CWE-208".to_string()),
                });
            }
        }
    }

    // Check for SSL/TLS implementation issues
    let ssl_functions = ["SSL_CTX_new", "SSL_new", "TLS_method"];
    let has_ssl = ssl_functions.iter().any(|&func| {
        analysis.imports.contains(&func.to_string())
            || analysis.detected_symbols.contains(&func.to_string())
    });

    if has_ssl {
        // Check for certificate verification bypass
        let dangerous_ssl_funcs = ["SSL_CTX_set_verify_mode", "SSL_set_verify"];
        for func in &dangerous_ssl_funcs {
            if analysis.imports.contains(&func.to_string())
                || analysis.detected_symbols.contains(&func.to_string())
            {
                issues.push(CryptoImplementationIssue {
                    issue_description: "SSL/TLS certificate verification may be disabled"
                        .to_string(),
                    location: CodeLocation {
                        file_path: analysis.file_name.clone(),
                        line_number: None,
                        column_number: None,
                        function_name: Some(func.to_string()),
                        binary_offset: None,
                    },
                    severity: SeverityLevel::High,
                    cwe_id: Some("CWE-295".to_string()),
                });
            }
        }

        // Check for insecure TLS versions
        if analysis
            .embedded_strings
            .iter()
            .any(|s| s.contains("SSLv3") || s.contains("TLSv1.0") || s.contains("TLSv1.1"))
        {
            issues.push(CryptoImplementationIssue {
                issue_description: "Insecure SSL/TLS version detected".to_string(),
                location: CodeLocation {
                    file_path: analysis.file_name.clone(),
                    line_number: None,
                    column_number: None,
                    function_name: None,
                    binary_offset: None,
                },
                severity: SeverityLevel::High,
                cwe_id: Some("CWE-326".to_string()),
            });
        }
    }

    issues
}

// Helper functions

fn has_crypto_context(analysis: &BinaryAnalysis) -> bool {
    let crypto_indicators = [
        "crypto", "cipher", "encrypt", "decrypt", "hash", "hmac", "aes", "rsa", "ecdsa", "ssl",
        "tls", "key", "openssl",
    ];

    for item in analysis
        .imports
        .iter()
        .chain(analysis.detected_symbols.iter())
        .chain(analysis.embedded_strings.iter())
        .chain(analysis.linked_libraries.iter())
    {
        let lower = item.to_lowercase();
        if crypto_indicators
            .iter()
            .any(|&indicator| lower.contains(indicator))
        {
            return true;
        }
    }
    false
}

fn is_likely_encoded_key(string: &str) -> bool {
    // Base64 pattern: 32+ chars, base64 alphabet, proper padding
    if string.len() >= 32 && string.len() % 4 == 0 {
        let base64_chars = string
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
        let padding_count = string.chars().filter(|&c| c == '=').count();

        if base64_chars && padding_count <= 2 {
            // Additional heuristic: high entropy
            let entropy = calculate_entropy_simple(string);
            return entropy > 4.5;
        }
    }
    false
}

fn is_hex_key_pattern(string: &str) -> bool {
    // 32+ hex characters (16+ bytes, suitable for keys)
    string.len() >= 32 && 
    string.len() <= 128 && // Reasonable upper bound
    string.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_api_key_pattern(string: &str) -> bool {
    let lower = string.to_lowercase();

    // Common API key prefixes
    let api_prefixes = [
        "api_key",
        "apikey",
        "api-key",
        "secret_key",
        "secretkey",
        "secret-key",
        "access_token",
        "accesstoken",
        "access-token",
        "bearer",
        "jwt",
        "aws_access_key",
        "aws_secret",
        "gcp_key",
        "azure_key",
    ];

    for prefix in &api_prefixes {
        if lower.contains(prefix) && string.len() > 20 {
            return true;
        }
    }

    // Pattern-based detection for common API key formats
    if string.len() >= 20 {
        // AWS-style keys
        if string.starts_with("AKIA") || string.starts_with("ASIA") {
            return true;
        }

        // Google API keys
        if string.starts_with("AIza") && string.len() == 39 {
            return true;
        }

        // GitHub tokens
        if string.starts_with("ghp_") || string.starts_with("gho_") || string.starts_with("ghu_") {
            return true;
        }
    }

    false
}

fn calculate_entropy_simple(string: &str) -> f32 {
    let mut char_counts = HashMap::new();
    for c in string.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = string.len() as f32;
    let mut entropy = 0.0;

    for count in char_counts.values() {
        let p = *count as f32 / len;
        entropy -= p * p.log2();
    }

    entropy
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
            detected_symbols: vec!["md5".to_string(), "rand".to_string()],
            embedded_strings: vec![
                "-----BEGIN RSA PRIVATE KEY-----".to_string(),
                "des_encrypt".to_string(),
                "ecb_mode".to_string(),
            ],
            suspected_secrets: vec![],
            imports: vec!["SSL_CTX_new".to_string(), "strcmp".to_string()],
            exports: vec![],
            hash_sha256: "test".to_string(),
            hash_blake3: None,
            size_bytes: 1024,
            linked_libraries: vec!["libssl.so.1.0.0".to_string()],
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
    fn test_analyze_crypto_security() {
        let analysis = create_test_analysis();
        let result = analyze_crypto_security(&analysis);

        assert_eq!(result.file_path, "test.bin");
        assert!(!result.key_issues.is_empty());
        assert!(!result.algorithm_issues.is_empty());
        assert!(!result.implementation_issues.is_empty());
    }

    #[test]
    fn test_detect_hardcoded_key() {
        let key_string = "-----BEGIN RSA PRIVATE KEY-----";
        let issue = detect_hardcoded_key(key_string, "test.bin");
        assert!(issue.is_some());
        assert!(matches!(
            issue.unwrap().issue_type,
            KeyIssueType::HardcodedKey
        ));
    }

    #[test]
    fn test_is_hex_key_pattern() {
        assert!(is_hex_key_pattern("0123456789abcdef0123456789abcdef"));
        assert!(!is_hex_key_pattern("short"));
        assert!(!is_hex_key_pattern("not_hex_at_all"));
    }

    #[test]
    fn test_is_api_key_pattern() {
        assert!(is_api_key_pattern("api_key_abcdef123456789"));
        assert!(is_api_key_pattern("AKIA1234567890123456"));
        assert!(!is_api_key_pattern("normal_string"));
    }
}
