// tests/binary_analysis_tests.rs

use nabla::binary::{analyze_binary, BinaryAnalysis};
use tokio;

#[tokio::test]
async fn test_analyze_binary_small_file() {
    let data = b"hello world"; // small, triggers small file path
    let analysis = analyze_binary("hello.txt", data).await.expect("analyze_binary failed");
    assert_eq!(analysis.file_name, "hello.txt");
    assert_eq!(analysis.size_bytes as usize, data.len());
}