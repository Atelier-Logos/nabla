// tests/binary_analysis_tests.rs

use nabla::binary::{analyze_binary, BinaryAnalysis, metadata_extractor::{VersionInfo, LicenseInfo}};
use nabla::enterprise::crypto::CryptoProvider;
use tokio;

// Helper function to create a test crypto provider
fn create_test_crypto_provider() -> CryptoProvider {
    CryptoProvider::new(false, false) // Use standard mode for tests
}

#[tokio::test]
async fn test_analyze_binary_small_file() {
    let data = b"hello world"; // small, triggers small file path
    let crypto_provider = create_test_crypto_provider();
    let analysis = analyze_binary("hello.txt", data, &crypto_provider).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, "hello.txt");
    assert_eq!(analysis.size_bytes as usize, data.len());
}

#[tokio::test]
async fn test_analyze_binary_empty_file() {
    let data = b"";
    let crypto_provider = create_test_crypto_provider();
    let analysis = analyze_binary("empty.bin", data, &crypto_provider).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, "empty.bin");
    assert_eq!(analysis.size_bytes, 0);
    assert_eq!(analysis.embedded_strings.len(), 0);
}

#[tokio::test]
async fn test_analyze_binary_large_file() {
    // Create a larger file to test different code paths
    let data = vec![0u8; 10000]; // 10KB file
    let crypto_provider = create_test_crypto_provider();
    let analysis = analyze_binary("large.bin", &data, &crypto_provider).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, "large.bin");
    assert_eq!(analysis.size_bytes as usize, data.len());
}

#[tokio::test]
async fn test_analyze_binary_with_special_chars() {
    let data = b"test data with special chars: !@#$%^&*()";
    let crypto_provider = create_test_crypto_provider();
    let analysis = analyze_binary("special@chars#file.bin", data, &crypto_provider).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, "special@chars#file.bin");
    assert_eq!(analysis.size_bytes as usize, data.len());
}

#[tokio::test]
async fn test_analyze_binary_unicode_filename() {
    let data = b"test data";
    let crypto_provider = create_test_crypto_provider();
    let analysis = analyze_binary("测试文件.bin", data, &crypto_provider).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, "测试文件.bin");
    assert_eq!(analysis.size_bytes as usize, data.len());
}

#[tokio::test]
async fn test_analyze_binary_very_long_filename() {
    let data = b"test data";
    let long_name = "a".repeat(255); // Very long filename
    let crypto_provider = create_test_crypto_provider();
    let analysis = analyze_binary(&long_name, data, &crypto_provider).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, long_name);
    assert_eq!(analysis.size_bytes as usize, data.len());
}

#[tokio::test]
async fn test_binary_analysis_struct() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec!["C".to_string()],
        detected_symbols: vec!["main".to_string()],
        embedded_strings: vec!["Hello, World!".to_string()],
        suspected_secrets: vec![],
        imports: vec!["libc.so.6".to_string()],
        exports: vec!["main".to_string()],
        hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        hash_blake3: Some("test_blake3_hash".to_string()),
        size_bytes: 1024,
        linked_libraries: vec!["libc.so.6".to_string()],
        static_linked: false,
        version_info: Some(VersionInfo {
            version_strings: vec!["1.0.0".to_string()],
            file_version: Some("1.0.0".to_string()),
            product_version: Some("1.0.0".to_string()),
            company: Some("Test Company".to_string()),
            product_name: Some("Test Product".to_string()),
            confidence: 0.8,
        }),
        license_info: Some(LicenseInfo {
            licenses: vec!["MIT".to_string()],
            copyright_notices: vec!["Copyright (c) 2024".to_string()],
            spdx_identifiers: vec!["MIT".to_string()],
            license_texts: vec!["Permission is hereby granted".to_string()],
            confidence: 0.9,
        }),
        metadata: serde_json::json!({"test": "value"}),
        created_at: chrono::Utc::now(),
        sbom: None,
    };
    
    assert_eq!(analysis.file_name, "test.bin");
    assert_eq!(analysis.format, "application/x-elf");
    assert_eq!(analysis.architecture, "x86_64");
    assert_eq!(analysis.languages.len(), 1);
    assert_eq!(analysis.detected_symbols.len(), 1);
    assert_eq!(analysis.embedded_strings.len(), 1);
    assert_eq!(analysis.imports.len(), 1);
    assert_eq!(analysis.exports.len(), 1);
    assert_eq!(analysis.size_bytes, 1024);
    assert_eq!(analysis.linked_libraries.len(), 1);
    assert!(!analysis.static_linked);
    assert!(analysis.version_info.is_some());
    assert!(analysis.license_info.is_some());
    assert!(analysis.hash_blake3.is_some());
}

#[test]
fn test_binary_analysis_serialization() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec![],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec![],
        exports: vec![],
        hash_sha256: "test_hash".to_string(),
        hash_blake3: None,
        size_bytes: 1024,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
    };
    
    // Test serialization
    let serialized = serde_json::to_string(&analysis).unwrap();
    assert!(serialized.contains("test.bin"));
    assert!(serialized.contains("application/x-elf"));
    assert!(serialized.contains("x86_64"));
    assert!(serialized.contains("test_hash"));
    assert!(serialized.contains("1024"));
    
    // Test deserialization
    let deserialized: BinaryAnalysis = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.file_name, "test.bin");
    assert_eq!(deserialized.format, "application/x-elf");
    assert_eq!(deserialized.architecture, "x86_64");
    assert_eq!(deserialized.size_bytes, 1024);
}

#[test]
fn test_binary_analysis_debug() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec![],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec![],
        exports: vec![],
        hash_sha256: "test_hash".to_string(),
        hash_blake3: None,
        size_bytes: 1024,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
    };
    
    let debug_str = format!("{:?}", analysis);
    assert!(debug_str.contains("test.bin"));
    assert!(debug_str.contains("application/x-elf"));
    assert!(debug_str.contains("x86_64"));
}

#[test]
fn test_binary_analysis_clone() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec![],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec![],
        exports: vec![],
        hash_sha256: "test_hash".to_string(),
        hash_blake3: None,
        size_bytes: 1024,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
    };
    
    let cloned_analysis = analysis.clone();
    assert_eq!(analysis.file_name, cloned_analysis.file_name);
    assert_eq!(analysis.format, cloned_analysis.format);
    assert_eq!(analysis.architecture, cloned_analysis.architecture);
    assert_eq!(analysis.size_bytes, cloned_analysis.size_bytes);
}