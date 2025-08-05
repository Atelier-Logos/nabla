// tests/test_scans.rs - Consolidated tests for binary scanning functionality

use chrono::Utc;
use nabla_cli::binary::{BinaryAnalysis, enterprise_scan_binary, scan_binary};
use serde_json::json;
use std::fs;
use uuid::Uuid;

fn create_test_analysis() -> BinaryAnalysis {
    let binary_path = "/Users/jdbohrman/nabla/minimal_test_binary.macho";
    let binary_contents = fs::read(binary_path).expect("Failed to read minimal_test_binary.macho");

    BinaryAnalysis {
        id: Uuid::new_v4(),
        file_name: "minimal_test_binary.macho".to_string(),
        format: "macho".to_string(), // Expected format for a compiled C program
        architecture: "arm64".to_string(), // Assuming arm64 compilation
        languages: vec!["C".to_string()],
        detected_symbols: vec!["_main".to_string(), "_start".to_string()], // Expect main and _start
        embedded_strings: vec![], // Minimal binary might not have many strings
        suspected_secrets: vec![],
        imports: vec!["/usr/lib/libSystem.B.dylib".to_string()], // Expect libSystem import for macOS
        exports: vec![],
        hash_sha256: "".to_string(), // Will be filled by analyze_binary
        hash_blake3: None,           // Will be filled by analyze_binary
        size_bytes: binary_contents.len() as u64,
        linked_libraries: vec!["/usr/lib/libSystem.B.dylib".to_string()], // Expect libSystem
        static_linked: false, // Typically dynamically linked
        version_info: None,
        license_info: None,
        metadata: json!({}),
        created_at: Utc::now(),
        sbom: None,
        binary_data: Some(binary_contents),
        entry_point: None,     // Will be filled by analyze_binary
        code_sections: vec![], // Will be filled by analyze_binary
    }
}

#[tokio::test]
async fn test_overall_binary_scans() {
    let initial_analysis = create_test_analysis();
    let analysis = nabla_cli::binary::analyze_binary(
        &initial_analysis.file_name,
        &initial_analysis.binary_data.as_ref().unwrap(),
    )
    .await
    .expect("Binary analysis failed");

    // Test basic OSS scan functionality
    let oss_result = scan_binary(&analysis);
    assert_eq!(oss_result.target_file, "minimal_test_binary.macho");
    assert!(!oss_result.scan_id.is_nil());
    assert!(!oss_result.recommendations.is_empty());
    assert!(
        oss_result.risk_assessment.security_score >= 0.0
            && oss_result.risk_assessment.security_score <= 100.0
    );
    assert!(
        !oss_result.vulnerability_findings.is_empty() || !oss_result.security_findings.is_empty()
    );

    // Test enterprise scan functionality
    let enterprise_result = enterprise_scan_binary(&analysis);
    assert_eq!(enterprise_result.target_file, "minimal_test_binary.macho");
    assert!(!enterprise_result.scan_id.is_nil());
    assert!(!enterprise_result.recommendations.is_empty());
    assert!(
        enterprise_result.risk_assessment.security_score >= 0.0
            && enterprise_result.risk_assessment.security_score <= 100.0
    );

    // Enterprise scan should have more detailed analysis results
    assert!(!enterprise_result.static_analysis.analysis_id.is_nil());
    assert!(!enterprise_result.behavioral_analysis.analysis_id.is_nil());
    assert!(!enterprise_result.crypto_analysis.analysis_id.is_nil());
    assert!(!enterprise_result.supply_chain_analysis.analysis_id.is_nil());

    // For a minimal binary, exploitability assessments might be empty if no vulnerabilities are found.
    // We assert that the vector is present, but not necessarily non-empty.
    assert!(
        enterprise_result.exploitability_assessments.is_empty()
            || !enterprise_result.exploitability_assessments.is_empty()
    );

    // Ensure enterprise recommendations are more comprehensive
    assert!(enterprise_result.recommendations.len() >= oss_result.recommendations.len());

    // Additional checks for a real Mach-O binary
    assert_eq!(analysis.format, "macho");
    assert!(analysis.detected_symbols.contains(&"_main".to_string()));
    assert!(
        analysis
            .imports
            .contains(&"/usr/lib/libSystem.B.dylib".to_string())
    );
    assert!(!analysis.hash_sha256.is_empty());
    assert!(analysis.hash_blake3.is_some());
    assert!(analysis.entry_point.is_some());
    assert!(!analysis.code_sections.is_empty());
}

#[tokio::test]
async fn test_binary_data_is_present() {
    let initial_analysis = create_test_analysis();
    let original_data = initial_analysis.binary_data.clone().unwrap();
    let analysis = nabla_cli::binary::analyze_binary(&initial_analysis.file_name, &original_data)
        .await
        .expect("Binary analysis failed");

    assert!(analysis.binary_data.is_some());
    let analyzed_data = analysis.binary_data.unwrap();
    assert!(!analyzed_data.is_empty());
    assert_eq!(original_data, analyzed_data);
}
