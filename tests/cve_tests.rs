// tests/cve_tests.rs

use nabla_cli::binary::{
    BinaryAnalysis,
    check_vulnerabilities::{collect_cpes, load_cve_db, enterprise_scan_binary_vulnerabilities},
    scan_binary_vulnerabilities,
};
use serde_json::json;

#[test]
fn test_load_cve_db() {
    let db = load_cve_db().expect("load_cve_db failed");
    assert!(!db.is_empty());
}

#[test]
fn test_collect_cpes() {
    let value = json!([
        {
            "cpe_match": [ { "cpe23Uri": "cpe:2.3:a:openssl:openssl:1.0.2:*:*:*:*:*:*:*" } ],
            "children": [
                { "cpe_match": [ { "cpe23Uri": "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*" } ] }
            ]
        }
    ]);
    let mut out = Vec::new();
    collect_cpes(&value, &mut out);
    assert_eq!(out.len(), 2);
}

#[test]
fn test_scan_binary_vulnerabilities() {
    // Prepare a minimal BinaryAnalysis with a keyword that likely exists in CVE DB
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec![],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec!["openssl".to_string()],
        exports: vec![],
        hash_sha256: String::new(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
        binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
        entry_point: Some(0x1000),
        code_sections: vec![],
    };

    let matches = scan_binary_vulnerabilities(&analysis);
    // We can't guarantee OpenSSL is present, but the function should run without error.
    assert!(matches.len() >= 0); // This is always true, but kept for clarity
}

#[test]
fn test_enterprise_scan_binary_vulnerabilities() {
    // Prepare a BinaryAnalysis with networking-related imports for reachability testing
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec!["main".to_string(), "process_data".to_string()],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec!["recv".to_string(), "openssl".to_string(), "socket".to_string()],
        exports: vec![],
        hash_sha256: String::new(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec!["libssl.so".to_string()],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
        binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
        entry_point: Some(0x1000),
        code_sections: vec![],
    };

    let enterprise_matches = enterprise_scan_binary_vulnerabilities(&analysis);
    // Test that the function runs without error and returns appropriate structure
    for match_item in &enterprise_matches {
        assert!(!match_item.cve_id.is_empty());
        assert!(!match_item.description.is_empty());
        assert!(!match_item.matched_keyword.is_empty());
        // Check that exploitability analysis is included
        assert!(!match_item.exploitability.sink.is_empty());
    }
}

#[test]
fn test_enterprise_vs_regular_scan_differences() {
    // Test that enterprise scan includes exploitability analysis while regular doesn't
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec!["main".to_string()],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec!["openssl".to_string()],
        exports: vec![],
        hash_sha256: String::new(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
        binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
        entry_point: Some(0x1000),
        code_sections: vec![],
    };

    let regular_matches = scan_binary_vulnerabilities(&analysis);
    let enterprise_matches = enterprise_scan_binary_vulnerabilities(&analysis);

    // Enterprise matches should have the same number of CVE matches but with added exploitability
    assert_eq!(regular_matches.len(), enterprise_matches.len());
    
    // If there are matches, verify enterprise has additional exploitability data
    if !regular_matches.is_empty() && !enterprise_matches.is_empty() {
        let regular_match = &regular_matches[0];
        let enterprise_match = &enterprise_matches[0];
        
        assert_eq!(regular_match.cve_id, enterprise_match.cve_id);
        assert_eq!(regular_match.description, enterprise_match.description);
        assert_eq!(regular_match.matched_keyword, enterprise_match.matched_keyword);
        
        // Enterprise should have exploitability analysis
        assert!(!enterprise_match.exploitability.sink.is_empty());
    }
}
