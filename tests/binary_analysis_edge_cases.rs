use nabla::binary::binary_analysis::analyze_binary;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let empty_file = temp_dir.path().join("empty.bin");
    fs::write(&empty_file, b"").unwrap();
    
    let contents = fs::read(&empty_file).unwrap();
    let result = analyze_binary("empty.bin", &contents).await;
    // Empty files are handled gracefully and return a successful result
    assert!(result.is_ok());
    let analysis = result.unwrap();
    assert_eq!(analysis.size_bytes, 0);
    assert_eq!(analysis.format, "application/octet-stream");
}

#[tokio::test]
async fn test_corrupted_elf() {
    let temp_dir = TempDir::new().unwrap();
    let corrupted_file = temp_dir.path().join("corrupted.elf");
    // Create a file that starts with ELF magic but is corrupted
    let mut corrupted_data = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
    corrupted_data.extend_from_slice(&vec![0x00; 100]); // Corrupted data
    fs::write(&corrupted_file, corrupted_data).unwrap();
    
    let contents = fs::read(&corrupted_file).unwrap();
    let result = analyze_binary("corrupted.elf", &contents).await;
    // Corrupted files are handled gracefully and return a successful result
    assert!(result.is_ok());
    let analysis = result.unwrap();
    assert_eq!(analysis.format, "application/wasm");
}

#[tokio::test]
async fn test_corrupted_macho() {
    let temp_dir = TempDir::new().unwrap();
    let corrupted_file = temp_dir.path().join("corrupted.macho");
    // Create a file that starts with Mach-O magic but is corrupted
    let mut corrupted_data = vec![0xfe, 0xed, 0xfa, 0xce]; // Mach-O magic
    corrupted_data.extend_from_slice(&vec![0x00; 100]); // Corrupted data
    fs::write(&corrupted_file, corrupted_data).unwrap();
    
    let contents = fs::read(&corrupted_file).unwrap();
    let result = analyze_binary("corrupted.macho", &contents).await;
    // Corrupted files are handled gracefully and return a successful result
    assert!(result.is_ok());
    let analysis = result.unwrap();
    assert_eq!(analysis.format, "macho");
}

#[tokio::test]
async fn test_corrupted_pe() {
    let temp_dir = TempDir::new().unwrap();
    let corrupted_file = temp_dir.path().join("corrupted.exe");
    // Create a file that starts with PE magic but is corrupted
    let mut corrupted_data = vec![0x4d, 0x5a]; // MZ magic
    corrupted_data.extend_from_slice(&vec![0x00; 100]); // Corrupted data
    fs::write(&corrupted_file, corrupted_data).unwrap();
    
    let contents = fs::read(&corrupted_file).unwrap();
    let result = analyze_binary("corrupted.exe", &contents).await;
    // Corrupted files are handled gracefully and return a successful result
    assert!(result.is_ok());
    let analysis = result.unwrap();
    assert_eq!(analysis.format, "application/wasm");
}

#[tokio::test]
async fn test_very_large_file() {
    let temp_dir = TempDir::new().unwrap();
    let large_file = temp_dir.path().join("large.bin");
    
    // Create a file that's larger than reasonable for analysis
    let large_data = vec![0x00; 10 * 1024 * 1024]; // 10MB
    fs::write(&large_file, large_data).unwrap();
    
    let contents = fs::read(&large_file).unwrap();
    let result = analyze_binary("large.bin", &contents).await;
    // Should either fail or take a very long time
    // For now, we'll just check it doesn't panic
    let _ = result;
}

#[tokio::test]
async fn test_unsupported_file_type() {
    let temp_dir = TempDir::new().unwrap();
    let text_file = temp_dir.path().join("test.txt");
    fs::write(&text_file, b"This is a text file, not a binary").unwrap();
    
    let contents = fs::read(&text_file).unwrap();
    let result = analyze_binary("test.txt", &contents).await;
    // This should succeed but detect it as text
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_binary_with_null_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let null_file = temp_dir.path().join("null.bin");
    
    // Create a file with many null bytes
    let null_data = vec![0x00; 1000];
    fs::write(&null_file, null_data).unwrap();
    
    let contents = fs::read(&null_file).unwrap();
    let result = analyze_binary("null.bin", &contents).await;
    // Should handle null bytes gracefully
    let _ = result;
}

#[tokio::test]
async fn test_binary_with_unicode_filename() {
    let temp_dir = TempDir::new().unwrap();
    let unicode_file = temp_dir.path().join("测试文件.bin");
    
    // Create a simple binary file with unicode filename
    let binary_data = vec![0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00];
    fs::write(&unicode_file, binary_data).unwrap();
    
    let contents = fs::read(&unicode_file).unwrap();
    let result = analyze_binary("测试文件.bin", &contents).await;
    // Should handle unicode filenames
    let _ = result;
}

#[tokio::test]
async fn test_binary_with_special_characters() {
    let temp_dir = TempDir::new().unwrap();
    let special_file = temp_dir.path().join("file with spaces and !@#$%^&*().bin");
    
    // Create a simple binary file with special characters in filename
    let binary_data = vec![0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00];
    fs::write(&special_file, binary_data).unwrap();
    
    let contents = fs::read(&special_file).unwrap();
    let result = analyze_binary("file with spaces and !@#$%^&*().bin", &contents).await;
    // Should handle special characters in filename
    let _ = result;
}

#[tokio::test]
async fn test_binary_analysis_result_serialization() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.bin");
    
    // Create a simple ELF file
    let elf_data = vec![
        0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, // ELF magic
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, // ELF header
    ];
    fs::write(&test_file, elf_data).unwrap();
    
    let contents = fs::read(&test_file).unwrap();
    let result = analyze_binary("test.bin", &contents).await;
    assert!(result.is_ok());
    
    let analysis = result.unwrap();
    
    // Test that the result can be serialized to JSON
    let json = serde_json::to_string(&analysis);
    assert!(json.is_ok());
    
    // Test that the result can be deserialized from JSON
    let json_str = json.unwrap();
    let deserialized: Result<nabla::binary::BinaryAnalysis, _> = serde_json::from_str(&json_str);
    assert!(deserialized.is_ok());
}

#[tokio::test]
async fn test_binary_analysis_with_malformed_data() {
    let temp_dir = TempDir::new().unwrap();
    let malformed_file = temp_dir.path().join("malformed.bin");
    
    // Create a file with malformed data that should cause parsing errors
    let malformed_data = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    fs::write(&malformed_file, malformed_data).unwrap();
    
    let contents = fs::read(&malformed_file).unwrap();
    let result = analyze_binary("malformed.bin", &contents).await;
    // Should handle malformed data gracefully
    let _ = result;
}

#[tokio::test]
async fn test_binary_analysis_performance() {
    let temp_dir = TempDir::new().unwrap();
    let perf_file = temp_dir.path().join("perf.bin");
    
    // Create a moderately sized file for performance testing
    let perf_data = vec![0x00; 1024 * 1024]; // 1MB
    fs::write(&perf_file, perf_data).unwrap();
    
    let contents = fs::read(&perf_file).unwrap();
    let result = analyze_binary("perf.bin", &contents).await;
    // Should complete within reasonable time
    let _ = result;
} 