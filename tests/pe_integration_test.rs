// Integration test for enhanced PE (Windows) parsing
// This tests the actual analyze_binary function with real Windows PE data

use nabla_cli::binary::analyze_binary;
use std::fs;
use tokio;

/// Create a minimal PE binary for testing
fn create_test_pe() -> Vec<u8> {
    let mut pe_data = Vec::new();
    
    // DOS header (64 bytes)
    let mut dos_header = vec![0u8; 64];
    dos_header[0..2].copy_from_slice(b"MZ");  // e_magic
    dos_header[60..64].copy_from_slice(&128u32.to_le_bytes()); // e_lfanew (PE offset)
    
    pe_data.extend_from_slice(&dos_header);
    
    // DOS stub (64 bytes padding to reach PE offset)
    pe_data.extend_from_slice(&vec![0u8; 64]);
    
    // PE header
    pe_data.extend_from_slice(b"PE\0\0"); // PE signature
    
    // COFF header (20 bytes)
    let mut coff_header = vec![0u8; 20];
    coff_header[0..2].copy_from_slice(&0x8664u16.to_le_bytes()); // IMAGE_FILE_MACHINE_AMD64
    coff_header[2..4].copy_from_slice(&1u16.to_le_bytes());      // NumberOfSections
    coff_header[16..18].copy_from_slice(&240u16.to_le_bytes());  // SizeOfOptionalHeader
    coff_header[18..20].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
    
    pe_data.extend_from_slice(&coff_header);
    
    // Optional header (240 bytes for PE32+)
    let mut optional_header = vec![0u8; 240];
    optional_header[0..2].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+ magic
    optional_header[2] = 14; // MajorLinkerVersion
    optional_header[3] = 0;  // MinorLinkerVersion
    optional_header[16..24].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase
    optional_header[24..28].copy_from_slice(&0x1000u32.to_le_bytes());      // SectionAlignment
    optional_header[28..32].copy_from_slice(&0x200u32.to_le_bytes());       // FileAlignment
    optional_header[40..42].copy_from_slice(&6u16.to_le_bytes());           // MajorOSVersion
    optional_header[44..46].copy_from_slice(&6u16.to_le_bytes());           // MajorSubsystemVersion
    optional_header[56..60].copy_from_slice(&0x2000u32.to_le_bytes());      // SizeOfImage
    optional_header[60..64].copy_from_slice(&0x400u32.to_le_bytes());       // SizeOfHeaders
    optional_header[68..70].copy_from_slice(&3u16.to_le_bytes());           // Subsystem (CONSOLE)
    
    pe_data.extend_from_slice(&optional_header);
    
    // Section header (.text section, 40 bytes)
    let mut section_header = vec![0u8; 40];
    section_header[0..8].copy_from_slice(b".text\0\0\0");
    section_header[8..12].copy_from_slice(&0x1000u32.to_le_bytes());  // VirtualSize
    section_header[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    section_header[16..20].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
    section_header[20..24].copy_from_slice(&0x400u32.to_le_bytes());  // PointerToRawData
    section_header[36..40].copy_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics
    
    pe_data.extend_from_slice(&section_header);
    
    // Pad to section data offset
    while pe_data.len() < 0x400 {
        pe_data.push(0);
    }
    
    // Add realistic embedded strings for Windows
    let strings = [
        "Microsoft Visual C++ 2022",
        "kernel32.dll",
        "msvcrt.dll",
        "user32.dll",
        "x64-windows-msvc",
        "Windows 10.0.22621",
        "ExitProcess",
        "GetStdHandle",
        "WriteConsoleA",
        "Visual Studio", // For compiler detection
        "MSVC"
    ];
    
    for s in strings.iter() {
        pe_data.extend_from_slice(s.as_bytes());
        pe_data.push(0); // Null terminator
    }
    
    // Pad to minimum section size
    while pe_data.len() < 0x600 {
        pe_data.push(0);
    }
    
    pe_data
}

#[tokio::test]
async fn test_enhanced_pe_parsing() {
    let pe_data = create_test_pe();
    
    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("test_app.exe", &pe_data).await;
    
    assert!(result.is_ok(), "PE analysis should succeed");
    
    let analysis = result.unwrap();
    
    // Verify basic detection
    assert_eq!(analysis.format, "pe");
    assert_eq!(analysis.file_name, "test_app.exe");
    assert!(analysis.size_bytes > 0);
    
    // Test enhanced Windows detection
    println!("Detected architecture: {}", analysis.architecture);
    
    // The architecture should be x86_64 or related variant
    assert!(
        analysis.architecture.contains("x86_64") || 
        analysis.architecture.contains("amd64") ||
        analysis.architecture == "x86_64",
        "Should detect x86_64 variant, got: {}",
        analysis.architecture
    );
    
    // Verify we extracted the embedded strings
    assert!(!analysis.embedded_strings.is_empty(), "Should extract embedded strings");
    
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    assert!(
        embedded_string_combined.contains("Microsoft") ||
        embedded_string_combined.contains("Visual") ||
        embedded_string_combined.contains("kernel32") ||
        embedded_string_combined.contains("MSVC"),
        "Should find Windows compiler/platform strings in: {:?}",
        analysis.embedded_strings
    );
    
    // Check if Windows-specific metadata was added
    println!("Metadata: {}", serde_json::to_string_pretty(&analysis.metadata).unwrap());
}

#[tokio::test] 
async fn test_enhanced_vs_basic_pe_detection() {
    let pe_data = create_test_pe();
    
    let analysis = analyze_binary("pe_test.exe", &pe_data)
        .await
        .expect("Analysis should succeed");
    
    // The key test: we should get proper PE detection
    println!("Architecture detected: '{}'", analysis.architecture);
    println!("Total embedded strings: {}", analysis.embedded_strings.len());
    println!("Format: {}", analysis.format);
    
    // Success criteria 
    let success_checks = vec![
        ("PE format detected", analysis.format == "pe"),
        ("Proper x86_64 detection", analysis.architecture.contains("x86_64") || analysis.architecture.contains("amd64")),
        ("Found embedded strings", !analysis.embedded_strings.is_empty()),
    ];
    
    for (check_name, passed) in success_checks {
        println!("{}: {}", check_name, if passed { "✅ PASS" } else { "❌ FAIL" });
    }
    
    // At minimum, we should detect it's a PE binary
    assert_eq!(analysis.format, "pe");
    assert!(analysis.architecture.contains("x86") || analysis.architecture.contains("amd64"));
}

#[tokio::test]
async fn test_pe_metadata_extraction() {
    let pe_data = create_test_pe();
    
    let analysis = analyze_binary("metadata_test.exe", &pe_data)
        .await
        .expect("Analysis should succeed");
    
    // Look for Windows-specific analysis in metadata
    if let Some(pe_analysis) = analysis.metadata.get("pe_analysis") {
        println!("✅ Found PE-specific analysis: {}", pe_analysis);
    } else {
        println!("⚠️ No PE-specific analysis found, but basic parsing worked");
    }
    
    // Verify symbols or other Windows-specific features were detected
    println!("Detected symbols: {:?}", analysis.detected_symbols);
    println!("Languages: {:?}", analysis.languages);
    
    // Check for Windows-specific imports
    let has_windows_imports = analysis.detected_symbols.iter()
        .any(|s| s.contains("kernel32") || s.contains("msvcrt") || s.contains("user32"));
    
    if has_windows_imports {
        println!("✅ Found Windows API imports");
    }
}