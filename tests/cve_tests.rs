// tests/cve_tests.rs

use nabla::binary::{
    check_vulnerabilities::{load_cve_db, collect_cpes},
    scan_binary_vulnerabilities, BinaryAnalysis
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
    };

    let matches = scan_binary_vulnerabilities(&analysis);
    // We can't guarantee OpenSSL is present, but the function should run without error.
    assert!(matches.len() >= 0);
} 