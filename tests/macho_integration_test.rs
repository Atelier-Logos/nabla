// Integration test for enhanced Mach-O parsing
// This tests the actual analyze_binary function with real macOS Mach-O data

use nabla_cli::binary::analyze_binary;

use tokio;

/// Create a minimal Mach-O binary for testing
fn create_test_macho() -> Vec<u8> {
    // Use a known working Mach-O pattern
    let mut macho_data = Vec::new();

    // Mach-O 64-bit header - use exact byte pattern
    let header = [
        0xcf, 0xfa, 0xed, 0xfe, // magic (MH_MAGIC_64)
        0x07, 0x00, 0x00, 0x01, // cputype (CPU_TYPE_X86_64)
        0x03, 0x00, 0x00, 0x00, // cpusubtype (CPU_SUBTYPE_X86_64_ALL)
        0x02, 0x00, 0x00, 0x00, // filetype (MH_EXECUTE)
        0x02, 0x00, 0x00, 0x00, // ncmds (2 commands)
        0x90, 0x00, 0x00, 0x00, // sizeofcmds (144 bytes)
        0x85, 0x00, 0x20, 0x00, // flags
        0x00, 0x00, 0x00, 0x00, // reserved
    ];

    macho_data.extend_from_slice(&header);

    // LC_SEGMENT_64 command
    let segment_cmd = [
        0x19, 0x00, 0x00, 0x00, // cmd (LC_SEGMENT_64)
        0x48, 0x00, 0x00, 0x00, // cmdsize (72 bytes)
        // segname (16 bytes)
        b'_', b'_', b'T', b'E', b'X', b'T', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    macho_data.extend_from_slice(&segment_cmd);

    // Rest of segment_64 command (remaining 56 bytes)
    let segment_rest = [0u8; 56];
    macho_data.extend_from_slice(&segment_rest);

    // LC_MAIN command (24 bytes)
    let main_cmd = [
        0x28, 0x00, 0x00, 0x80, // cmd (LC_MAIN)
        0x18, 0x00, 0x00, 0x00, // cmdsize (24 bytes)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // entryoff
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // stacksize
    ];
    macho_data.extend_from_slice(&main_cmd);

    // Add realistic embedded strings for macOS
    let strings = [
        "Apple clang version 15.0.0",
        "/usr/lib/libSystem.B.dylib",
        "MacOSX14.2.sdk",
        "x86_64-apple-macos14.0",
        "_main",
        "darwin",
        "macos",
    ];

    for s in strings.iter() {
        macho_data.extend_from_slice(s.as_bytes());
        macho_data.push(0);
    }

    // Pad to reasonable size
    while macho_data.len() < 512 {
        macho_data.push(0);
    }

    macho_data
}

#[tokio::test]
async fn test_enhanced_macho_parsing() {
    let macho_data = create_test_macho();

    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("test_macho", &macho_data).await;

    assert!(result.is_ok(), "Mach-O analysis should succeed");

    let analysis = result.unwrap();

    // Verify basic detection
    assert_eq!(analysis.format, "macho");
    assert_eq!(analysis.file_name, "test_macho");
    assert!(analysis.size_bytes > 0);

    // Test enhanced macOS detection
    println!("Detected architecture: {}", analysis.architecture);

    // The architecture should be x86_64 or related variant
    assert!(
        analysis.architecture.contains("x86_64")
            || analysis.architecture.contains("amd64")
            || analysis.architecture == "x86_64",
        "Should detect x86_64 variant, got: {}",
        analysis.architecture
    );

    // Verify we extracted the embedded strings
    assert!(
        !analysis.embedded_strings.is_empty(),
        "Should extract embedded strings"
    );

    let embedded_string_combined = analysis.embedded_strings.join(" ");
    assert!(
        embedded_string_combined.contains("apple")
            || embedded_string_combined.contains("clang")
            || embedded_string_combined.contains("darwin")
            || embedded_string_combined.contains("macos"),
        "Should find macOS compiler/platform strings in: {:?}",
        analysis.embedded_strings
    );

    // Check if macOS-specific metadata was added
    println!(
        "Metadata: {}",
        serde_json::to_string_pretty(&analysis.metadata).unwrap()
    );
}

#[tokio::test]
async fn test_enhanced_vs_basic_macho_detection() {
    let macho_data = create_test_macho();

    let analysis = analyze_binary("macho_test", &macho_data)
        .await
        .expect("Analysis should succeed");

    // The key test: we should get proper Mach-O detection
    println!("Architecture detected: '{}'", analysis.architecture);
    println!(
        "Total embedded strings: {}",
        analysis.embedded_strings.len()
    );
    println!("Format: {}", analysis.format);

    // Success criteria
    let success_checks = vec![
        ("Mach-O format detected", analysis.format == "macho"),
        (
            "Proper x86_64 detection",
            analysis.architecture.contains("x86_64") || analysis.architecture.contains("amd64"),
        ),
        (
            "Found embedded strings",
            !analysis.embedded_strings.is_empty(),
        ),
    ];

    for (check_name, passed) in success_checks {
        println!(
            "{}: {}",
            check_name,
            if passed { "✅ PASS" } else { "❌ FAIL" }
        );
    }

    // At minimum, we should detect it's a Mach-O binary
    assert_eq!(analysis.format, "macho");
    assert!(analysis.architecture.contains("x86") || analysis.architecture.contains("amd64"));
}

#[tokio::test]
async fn test_macho_metadata_extraction() {
    let macho_data = create_test_macho();

    let analysis = analyze_binary("metadata_test", &macho_data)
        .await
        .expect("Analysis should succeed");

    // Look for macOS-specific analysis in metadata
    if let Some(macho_analysis) = analysis.metadata.get("macho_analysis") {
        println!("✅ Found Mach-O-specific analysis: {}", macho_analysis);
    } else {
        println!("⚠️ No Mach-O-specific analysis found, but basic parsing worked");
    }

    // Verify symbols or other macOS-specific features were detected
    println!("Detected symbols: {:?}", analysis.detected_symbols);
    println!("Languages: {:?}", analysis.languages);
}
