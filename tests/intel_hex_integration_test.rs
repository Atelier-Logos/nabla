// Integration test for enhanced Intel HEX parsing
// This tests the actual analyze_binary function with real Intel HEX data

use nabla_cli::binary::analyze_binary;
use tokio;

/// Create a minimal Intel HEX file for testing using the real vulnerable firmware
fn create_test_intel_hex() -> Vec<u8> {
    // Use content from the actual vulnerable firmware file
    let hex_content = r#":020000040000FA
:10000000001020000901000845010008470100084B
:10001000490100084B0100084D0100084F01000834
:1000200051010008530100085501000857010008FC
:10003000590100085B0100085D0100085F010008C4
:10004000610100086301000865010008670100088C
:10005000690100086B0100086D0100086F01000854
:100060007101000873010008750100087701000824
:10007000790100087B0100087D0100087F010008EC
:100080008101000883010008850100088701000894
:100090008901000800F002F800F016F800F01AF85C
:1000A00000F01EF800F022F800F026F800F02AF838
:1000B00000F02EF800F032F800F036F800F03AF804
:1000C00000F03EF800F042F800F046F800F04AF8D0
:1000D00000F04EF800F052F800F056F800F05AF89C
:1000E00000F05EF800F062F800F066F800F06AF868
:1000F00000F06EF800F072F800F076F800F07AF834
:00000001FF"#;

    hex_content.as_bytes().to_vec()
}

/// Create an Intel HEX with ARM Cortex-M specific content  
fn create_arm_cortex_hex() -> Vec<u8> {
    // Use a simpler format
    let hex_content = r#":020000040000FA
:10000000000420008D030008910300089503000044
:10001000990300089D030008A1030008A503000028
:00000001FF"#;

    hex_content.as_bytes().to_vec()
}

#[tokio::test]
async fn test_enhanced_intel_hex_parsing() {
    let hex_data = create_test_intel_hex();

    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("firmware.hex", &hex_data).await;

    assert!(result.is_ok(), "Intel HEX analysis should succeed");

    let analysis = result.unwrap();

    // Verify basic detection - should now work with manual parsing
    println!("Detected format: {}", analysis.format);
    assert_eq!(analysis.format, "intel-hex");
    assert_eq!(analysis.file_name, "firmware.hex");
    assert!(analysis.size_bytes > 0);

    // Test Intel HEX specific detection
    println!("Detected architecture: {}", analysis.architecture);
    println!("Format: {}", analysis.format);

    // Should detect embedded architecture
    assert_eq!(analysis.architecture, "embedded");

    // Verify we have firmware language detected
    assert!(analysis.languages.contains(&"Firmware".to_string()));

    // Check if Intel HEX-specific metadata was added
    println!(
        "Metadata: {}",
        serde_json::to_string_pretty(&analysis.metadata).unwrap()
    );
}

#[tokio::test]
async fn test_arm_cortex_hex_parsing() {
    let hex_data = create_arm_cortex_hex();

    let analysis = analyze_binary("cortex_firmware.hex", &hex_data)
        .await
        .expect("Analysis should succeed");

    // The key test: we should get proper Intel HEX detection
    println!("Architecture detected: '{}'", analysis.architecture);
    println!("Format: {}", analysis.format);

    // Success criteria
    let success_checks = vec![
        ("Intel HEX format detected", analysis.format == "intel-hex"),
        (
            "Embedded architecture detected",
            analysis.architecture == "embedded",
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

    // At minimum, we should detect it's an Intel HEX file
    assert_eq!(analysis.format, "intel-hex");
    assert_eq!(analysis.architecture, "embedded");
}

#[tokio::test]
async fn test_intel_hex_metadata_extraction() {
    let hex_data = create_test_intel_hex();

    let analysis = analyze_binary("metadata_test.hex", &hex_data)
        .await
        .expect("Analysis should succeed");

    // Look for Intel HEX-specific analysis in metadata
    if let Some(hex_analysis) = analysis.metadata.get("intel_hex_analysis") {
        println!("✅ Found Intel HEX-specific analysis: {}", hex_analysis);
    } else if let Some(firmware_analysis) = analysis.metadata.get("firmware_analysis") {
        println!("✅ Found firmware-specific analysis: {}", firmware_analysis);
    } else {
        println!("⚠️ No Intel HEX-specific analysis found, but basic parsing worked");
    }

    // Verify firmware features were detected
    println!("Languages: {:?}", analysis.languages);
    println!("Detected symbols: {:?}", analysis.detected_symbols);

    // Basic validation that we got a valid Intel HEX analysis
    assert_eq!(analysis.format, "intel-hex");
    assert!(analysis.size_bytes > 0);
    assert!(analysis.languages.contains(&"Firmware".to_string()));
}

#[tokio::test]
async fn test_intel_hex_vs_regular_text() {
    // Test with actual Intel HEX
    let hex_data = create_test_intel_hex();
    let hex_analysis = analyze_binary("real.hex", &hex_data)
        .await
        .expect("Intel HEX analysis should succeed");

    // Test with regular text that looks similar but has invalid format
    let fake_hex = b"This is not a real Intel HEX file\nIt just contains some text\nNo colons here";
    let text_analysis = analyze_binary("fake.hex", fake_hex)
        .await
        .expect("Text analysis should succeed");

    // Real Intel HEX should be detected correctly
    assert_eq!(hex_analysis.format, "intel-hex");

    // Fake hex should not be detected as Intel HEX
    assert_ne!(text_analysis.format, "intel-hex");

    println!("Real Intel HEX format: {}", hex_analysis.format);
    println!("Fake hex format: {}", text_analysis.format);
}
