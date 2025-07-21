// tests/binary_analysis_tests.rs

use nabla::binary::{analyze_binary, generate_sbom, BinaryAnalysis};
use tokio;

#[tokio::test]
async fn test_analyze_binary_small_file() {
    let data = b"hello world"; // small, triggers small file path
    let analysis = analyze_binary("hello.txt", data).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, "hello.txt");
    assert_eq!(analysis.size_bytes as usize, data.len());
}

#[tokio::test]
async fn test_generate_sbom() {
    let mut analysis = analyze_binary("hello.txt", b"hello world").await.expect("analysis");
    // generate sbom
    let sbom = generate_sbom(&analysis).expect("generate_sbom failed");
    // attach and basic assert
    analysis.sbom = Some(sbom.clone());
    assert!(sbom.get("bomFormat").is_some());
} 