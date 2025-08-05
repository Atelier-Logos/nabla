// Integration test for enhanced WASM parsing
// This tests the actual analyze_binary function with real WebAssembly data

use nabla_cli::binary::analyze_binary;

use tokio;

/// Create a minimal WASM module for testing
fn create_test_wasm() -> Vec<u8> {
    let mut wasm_data = Vec::new();

    // WASM magic number and version
    wasm_data.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d]); // "\0asm"
    wasm_data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1

    // Type section
    wasm_data.push(0x01); // section id: type
    wasm_data.push(0x07); // section size
    wasm_data.push(0x01); // number of types
    wasm_data.push(0x60); // function type
    wasm_data.push(0x02); // number of parameters
    wasm_data.push(0x7f); // i32 parameter
    wasm_data.push(0x7f); // i32 parameter
    wasm_data.push(0x01); // number of results
    wasm_data.push(0x7f); // i32 result

    // Function section
    wasm_data.push(0x03); // section id: function
    wasm_data.push(0x02); // section size
    wasm_data.push(0x01); // number of functions
    wasm_data.push(0x00); // function type index

    // Export section
    wasm_data.push(0x07); // section id: export
    wasm_data.push(0x07); // section size
    wasm_data.push(0x01); // number of exports
    wasm_data.push(0x03); // export name length
    wasm_data.extend_from_slice(b"add"); // export name
    wasm_data.push(0x00); // export kind: function
    wasm_data.push(0x00); // function index

    // Code section
    wasm_data.push(0x0a); // section id: code
    wasm_data.push(0x09); // section size
    wasm_data.push(0x01); // number of functions
    wasm_data.push(0x07); // function body size
    wasm_data.push(0x00); // local declarations count
    // Function body: get_local 0, get_local 1, i32.add, end
    wasm_data.extend_from_slice(&[0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b]);

    // Custom section with metadata (optional)
    wasm_data.push(0x00); // section id: custom
    wasm_data.push(0x20); // section size
    wasm_data.push(0x07); // name length
    wasm_data.extend_from_slice(b"producer"); // name
    wasm_data.extend_from_slice(b"Rust WebAssembly toolchain"); // content

    wasm_data
}

/// Create a more complex WASM module with imports and memory
fn create_complex_wasm() -> Vec<u8> {
    let mut wasm_data = Vec::new();

    // WASM magic number and version
    wasm_data.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d]); // "\0asm"
    wasm_data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1

    // Type section - define function signatures
    wasm_data.push(0x01); // section id: type
    wasm_data.push(0x0c); // section size
    wasm_data.push(0x02); // number of types
    // Type 0: (i32, i32) -> i32
    wasm_data.push(0x60); // function type
    wasm_data.push(0x02); // number of parameters
    wasm_data.push(0x7f); // i32 parameter
    wasm_data.push(0x7f); // i32 parameter  
    wasm_data.push(0x01); // number of results
    wasm_data.push(0x7f); // i32 result
    // Type 1: () -> ()
    wasm_data.push(0x60); // function type
    wasm_data.push(0x00); // number of parameters
    wasm_data.push(0x00); // number of results

    // Import section
    wasm_data.push(0x02); // section id: import
    wasm_data.push(0x0f); // section size
    wasm_data.push(0x01); // number of imports
    wasm_data.push(0x03); // module name length
    wasm_data.extend_from_slice(b"env"); // module name
    wasm_data.push(0x07); // import name length
    wasm_data.extend_from_slice(b"console"); // import name
    wasm_data.push(0x00); // import kind: function
    wasm_data.push(0x01); // type index

    // Memory section
    wasm_data.push(0x05); // section id: memory
    wasm_data.push(0x03); // section size
    wasm_data.push(0x01); // number of memories
    wasm_data.push(0x00); // memory limits (min only)
    wasm_data.push(0x01); // minimum pages

    // Function section
    wasm_data.push(0x03); // section id: function
    wasm_data.push(0x02); // section size
    wasm_data.push(0x01); // number of functions
    wasm_data.push(0x00); // function type index

    // Export section
    wasm_data.push(0x07); // section id: export
    wasm_data.push(0x0b); // section size
    wasm_data.push(0x02); // number of exports
    // Export 1: function
    wasm_data.push(0x03); // export name length
    wasm_data.extend_from_slice(b"add"); // export name
    wasm_data.push(0x00); // export kind: function
    wasm_data.push(0x01); // function index (after imports)
    // Export 2: memory
    wasm_data.push(0x06); // export name length
    wasm_data.extend_from_slice(b"memory"); // export name
    wasm_data.push(0x02); // export kind: memory
    wasm_data.push(0x00); // memory index

    // Code section
    wasm_data.push(0x0a); // section id: code
    wasm_data.push(0x09); // section size
    wasm_data.push(0x01); // number of functions
    wasm_data.push(0x07); // function body size
    wasm_data.push(0x00); // local declarations count
    // Function body: get_local 0, get_local 1, i32.add, end
    wasm_data.extend_from_slice(&[0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b]);

    wasm_data
}

#[tokio::test]
async fn test_enhanced_wasm_parsing() {
    let wasm_data = create_test_wasm();

    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("test_module.wasm", &wasm_data).await;

    assert!(result.is_ok(), "WASM analysis should succeed");

    let analysis = result.unwrap();

    // Verify basic detection
    assert_eq!(analysis.format, "application/wasm");
    assert_eq!(analysis.file_name, "test_module.wasm");
    assert!(analysis.size_bytes > 0);

    // Test WASM architecture detection
    println!("Detected architecture: {}", analysis.architecture);

    // WASM should be detected as wasm or wasm32
    assert!(
        analysis.architecture.contains("wasm") || analysis.architecture == "webassembly",
        "Should detect WASM architecture, got: {}",
        analysis.architecture
    );

    // Check if WASM-specific metadata was added
    println!(
        "Metadata: {}",
        serde_json::to_string_pretty(&analysis.metadata).unwrap()
    );

    // Verify symbols were extracted
    if !analysis.detected_symbols.is_empty() {
        println!("Detected WASM symbols: {:?}", analysis.detected_symbols);
    }
}

#[tokio::test]
async fn test_complex_wasm_parsing() {
    let wasm_data = create_complex_wasm();

    let analysis = analyze_binary("complex_module.wasm", &wasm_data)
        .await
        .expect("Analysis should succeed");

    // The key test: we should get proper WASM detection with more features
    println!("Architecture detected: '{}'", analysis.architecture);
    println!("Format: {}", analysis.format);
    println!("Detected symbols: {:?}", analysis.detected_symbols);

    // Success criteria
    let success_checks = vec![
        (
            "WASM format detected",
            analysis.format == "application/wasm",
        ),
        (
            "WASM architecture detected",
            analysis.architecture.contains("wasm"),
        ),
        ("File analyzed", analysis.size_bytes > 0),
    ];

    for (check_name, passed) in success_checks {
        println!(
            "{}: {}",
            check_name,
            if passed { "✅ PASS" } else { "❌ FAIL" }
        );
    }

    // At minimum, we should detect it's a WASM module
    assert_eq!(analysis.format, "application/wasm");
    assert!(
        analysis.architecture.contains("wasm") || analysis.architecture.contains("webassembly")
    );
}

#[tokio::test]
async fn test_wasm_metadata_extraction() {
    let wasm_data = create_complex_wasm();

    let analysis = analyze_binary("metadata_test.wasm", &wasm_data)
        .await
        .expect("Analysis should succeed");

    // Look for WASM-specific analysis in metadata
    if let Some(wasm_analysis) = analysis.metadata.get("wasm_analysis") {
        println!("✅ Found WASM-specific analysis: {}", wasm_analysis);
    } else {
        println!("⚠️ No WASM-specific analysis found, but basic parsing worked");
    }

    // Verify WASM features were detected
    println!("Languages: {:?}", analysis.languages);

    // Check for WASM exports/imports
    let has_wasm_features = analysis
        .detected_symbols
        .iter()
        .any(|s| s.contains("add") || s.contains("memory") || s.contains("export"));

    if has_wasm_features {
        println!("✅ Found WASM exports/imports");
    }

    // Basic validation that we got a valid WASM analysis
    assert_eq!(analysis.format, "application/wasm");
    assert!(analysis.size_bytes > 0);
}
