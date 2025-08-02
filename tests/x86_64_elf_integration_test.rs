// Integration test for enhanced x86_64 ELF parsing
// This tests the actual analyze_binary function with real x86_64 ELF data

use nabla_cli::binary::analyze_binary;
use std::fs;
use tokio;

/// Create a minimal x86_64 ELF binary for testing
fn create_test_x86_64_elf() -> Vec<u8> {
    let mut elf_data = Vec::new();
    
    // ELF header (64 bytes for 64-bit x86_64)
    let mut header = vec![0u8; 64];
    
    // Magic number
    header[0..4].copy_from_slice(b"\x7fELF");
    header[4] = 2; // 64-bit
    header[5] = 1; // Little endian
    header[6] = 1; // ELF version
    header[7] = 0; // System V ABI
    
    // ELF header fields (little-endian)
    header[16..18].copy_from_slice(&2u16.to_le_bytes());  // ET_EXEC
    header[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    header[20..24].copy_from_slice(&1u32.to_le_bytes());  // e_version
    header[24..32].copy_from_slice(&0x400000u64.to_le_bytes()); // e_entry
    header[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    
    header[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    header[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    header[56..58].copy_from_slice(&1u16.to_le_bytes());  // e_phnum
    
    elf_data.extend_from_slice(&header);
    
    // Program header (56 bytes for 64-bit)
    let mut ph = vec![0u8; 56];
    ph[0..4].copy_from_slice(&1u32.to_le_bytes());         // PT_LOAD
    ph[8..16].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    ph[16..24].copy_from_slice(&0x400000u64.to_le_bytes());// p_paddr
    ph[32..40].copy_from_slice(&300u64.to_le_bytes());     // p_filesz
    ph[40..48].copy_from_slice(&300u64.to_le_bytes());     // p_memsz
    ph[4..8].copy_from_slice(&5u32.to_le_bytes());         // p_flags (R+X)
    
    elf_data.extend_from_slice(&ph);
    
    // Add realistic embedded strings for x86_64
    let strings = [
        "GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libm.so.6", 
        "x86_64-linux-gnu-gcc",
        "x86_64-pc-linux-gnu",
        "__libc_start_main",
        "printf",
        "malloc",
        "AMD64", // For architecture detection
        "Intel x86_64"
    ];
    
    for s in strings.iter() {
        elf_data.extend_from_slice(s.as_bytes());
        elf_data.push(0); // Null terminator
    }
    
    // Pad to minimum size
    while elf_data.len() < 300 {
        elf_data.push(0);
    }
    
    elf_data
}

#[tokio::test]
async fn test_enhanced_x86_64_elf_parsing() {
    let x86_64_elf_data = create_test_x86_64_elf();
    
    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("test_x86_64.elf", &x86_64_elf_data).await;
    
    assert!(result.is_ok(), "x86_64 ELF analysis should succeed");
    
    let analysis = result.unwrap();
    
    // Verify basic detection
    assert_eq!(analysis.format, "elf");
    assert_eq!(analysis.file_name, "test_x86_64.elf");
    assert!(analysis.size_bytes > 0);
    
    // Test enhanced x86_64 detection
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
        embedded_string_combined.contains("x86_64-linux-gnu") ||
        embedded_string_combined.contains("GCC") ||
        embedded_string_combined.contains("AMD64"),
        "Should find x86_64 compiler strings in: {:?}",
        analysis.embedded_strings
    );
    
    // Check if x86_64-specific metadata was added
    println!("Metadata: {}", serde_json::to_string_pretty(&analysis.metadata).unwrap());
}

#[tokio::test] 
async fn test_enhanced_vs_basic_x86_64_detection() {
    let x86_64_elf_data = create_test_x86_64_elf();
    
    let analysis = analyze_binary("x86_64_test.elf", &x86_64_elf_data)
        .await
        .expect("Analysis should succeed");
    
    // The key test: we should get proper x86_64 detection
    println!("Architecture detected: '{}'", analysis.architecture);
    println!("Total embedded strings: {}", analysis.embedded_strings.len());
    
    // Success criteria 
    let success_checks = vec![
        ("Proper x86_64 detection", analysis.architecture.contains("x86_64") || analysis.architecture.contains("amd64")),
        ("Found embedded strings", !analysis.embedded_strings.is_empty()),
        ("ELF format detected", analysis.format == "elf"),
    ];
    
    for (check_name, passed) in success_checks {
        println!("{}: {}", check_name, if passed { "✅ PASS" } else { "❌ FAIL" });
    }
    
    // At minimum, we should detect it's an x86_64 ELF
    assert_eq!(analysis.format, "elf");
    assert!(analysis.architecture.contains("x86") || analysis.architecture.contains("amd64"));
}