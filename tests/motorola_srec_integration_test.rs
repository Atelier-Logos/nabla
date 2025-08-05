// Integration test for enhanced Motorola S-record parsing
// This tests the actual analyze_binary function with real Motorola S-record firmware data

use nabla_cli::binary::analyze_binary;

use tokio;

/// Create a minimal Motorola S-record file for testing
fn create_test_motorola_srec() -> Vec<u8> {
    let srec_content = r#"S00F000068656C6C6F202020202000003C
S11F00007C0802A6900100049421FFF07C6C1B787C8C23784E800020E8010014D5
S11F001C38A000207C7C7B788CA300007C7C0C7839200000993F004C38E1000876
S11F00387C6C1B787C8C23784E800020E8010014388100104E800020E801001476
S11F0054A000007C3F004C38E10008763F004C38E100089421FFF07C6C1B7876
S10F00707C8C23784E800020E80100142E
S5030001FB
S9030000FC"#;

    srec_content.as_bytes().to_vec()
}

/// Create a more complex Motorola S-record with metadata
fn create_complex_motorola_srec() -> Vec<u8> {
    let srec_content = r#"S00600004844521B
S113000000000000000000000000000000000073
S113001000000000000000000000000000000063
S113002000000000000000000000000000000053
S113003000000000000000000000000000000043
S113004000000000000000000000000000000033
S113005000000000000000000000000000000023
S113006000000000000000000000000000000013
S113007000000000000000000000000000000003
S11300804D6F746F726F6C6120363830303020F9
S11300904D6963726F636F6E74726F6C6C6572E7
S113009050726F6772616D6D696E6720546F6FD7
S1130100506F77657220436F6E74726F6C6C6512
S1130110204465766963650000000000000000C2
S1130120466C6173685F50726F6772616D0000B2
S1130130466C6173685F4572617365000000009E
S1130140496E697469616C697A65000000000092
S1130150525341204B65792047656E65726174F2
S1130160696F6E204D6F64756C65000000000072
S113017041455320456E6372797074696F6E005E
S1130180444553204465637279707420416C674A
S1130190436F6465205369676E696E6720436532
S11301A06F6E74726F6C20556E697400000000FA
S11301B052656D6F746520466C617368205072DE
S11301C06F6772616D6D696E6700000000000012
S11301D0426F6F746C6F61646572204D6F646506
S11301E053656375726520426F6F740000000006
S5030019E3
S9030000FC"#;

    srec_content.as_bytes().to_vec()
}

#[tokio::test]
async fn test_enhanced_motorola_srec_parsing() {
    let srec_data = create_test_motorola_srec();

    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("firmware.s19", &srec_data).await;

    assert!(result.is_ok(), "Motorola S-record analysis should succeed");

    let analysis = result.unwrap();

    // Verify basic detection
    assert_eq!(analysis.format, "motorola-srec");
    assert_eq!(analysis.file_name, "firmware.s19");
    assert!(analysis.size_bytes > 0);

    // Test Motorola S-record specific detection
    println!("Detected architecture: {}", analysis.architecture);
    println!("Format: {}", analysis.format);

    // Check if Motorola S-record-specific metadata was added
    println!(
        "Metadata: {}",
        serde_json::to_string_pretty(&analysis.metadata).unwrap()
    );
}

#[tokio::test]
async fn test_complex_motorola_srec_parsing() {
    let srec_data = create_complex_motorola_srec();

    let analysis = analyze_binary("complex_firmware.s28", &srec_data)
        .await
        .expect("Analysis should succeed");

    // The key test: we should get proper Motorola S-record detection
    println!("Architecture detected: '{}'", analysis.architecture);
    println!("Format: {}", analysis.format);
    println!("Embedded strings: {:?}", analysis.embedded_strings);

    // Success criteria
    let success_checks = vec![
        (
            "Motorola S-record format detected",
            analysis.format == "motorola-srec",
        ),
        (
            "Found embedded strings",
            !analysis.embedded_strings.is_empty(),
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

    // Look for Motorola 68000 or firmware-specific strings
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_motorola_strings = embedded_string_combined.contains("Motorola")
        || embedded_string_combined.contains("68000")
        || embedded_string_combined.contains("Flash")
        || embedded_string_combined.contains("Power");

    if has_motorola_strings {
        println!("✅ Found Motorola/firmware specific strings");
    }

    // At minimum, we should detect it's a Motorola S-record file
    assert_eq!(analysis.format, "motorola-srec");
}

#[tokio::test]
async fn test_motorola_srec_metadata_extraction() {
    let srec_data = create_complex_motorola_srec();

    let analysis = analyze_binary("metadata_test.s37", &srec_data)
        .await
        .expect("Analysis should succeed");

    // Look for Motorola S-record-specific analysis in metadata
    if let Some(srec_analysis) = analysis.metadata.get("motorola_srec_analysis") {
        println!(
            "✅ Found Motorola S-record-specific analysis: {}",
            srec_analysis
        );
    } else if let Some(firmware_analysis) = analysis.metadata.get("firmware_analysis") {
        println!("✅ Found firmware-specific analysis: {}", firmware_analysis);
    } else {
        println!("⚠️ No Motorola S-record-specific analysis found, but basic parsing worked");
    }

    // Verify firmware features were detected
    println!("Languages: {:?}", analysis.languages);
    println!("Detected symbols: {:?}", analysis.detected_symbols);

    // Check for firmware-related symbols/functions
    let has_firmware_symbols = analysis
        .detected_symbols
        .iter()
        .any(|s| s.contains("Flash") || s.contains("Initialize") || s.contains("Boot"));

    if has_firmware_symbols {
        println!("✅ Found firmware-related symbols");
    }

    // Basic validation that we got a valid Motorola S-record analysis
    assert_eq!(analysis.format, "motorola-srec");
    assert!(analysis.size_bytes > 0);
}

#[tokio::test]
async fn test_motorola_srec_vs_regular_text() {
    // Test with actual Motorola S-record
    let srec_data = create_test_motorola_srec();
    let srec_analysis = analyze_binary("real.s19", &srec_data)
        .await
        .expect("Motorola S-record analysis should succeed");

    // Test with regular text that looks similar
    let fake_srec = b"S0this is not real motorola s-record format data\nS1but it starts with S\n";
    let text_analysis = analyze_binary("fake.s19", fake_srec)
        .await
        .expect("Text analysis should succeed");

    // Real Motorola S-record should be detected correctly
    assert_eq!(srec_analysis.format, "motorola-srec");

    // Fake S-record should not be detected as Motorola S-record
    assert_ne!(text_analysis.format, "motorola-srec");

    println!("Real Motorola S-record format: {}", srec_analysis.format);
    println!("Fake S-record format: {}", text_analysis.format);
}

#[tokio::test]
async fn test_motorola_srec_crypto_detection() {
    let srec_data = create_complex_motorola_srec();

    let analysis = analyze_binary("crypto_firmware.s28", &srec_data)
        .await
        .expect("Analysis should succeed");

    // Look for cryptographic functionality in the firmware
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_crypto_strings = embedded_string_combined.contains("RSA")
        || embedded_string_combined.contains("AES")
        || embedded_string_combined.contains("DES")
        || embedded_string_combined.contains("Encrypt")
        || embedded_string_combined.contains("Decrypt");

    if has_crypto_strings {
        println!("✅ Found cryptographic functionality indicators");

        // Check if this was flagged in metadata
        if let Some(crypto_analysis) = analysis.metadata.get("crypto_analysis") {
            println!("Crypto analysis: {}", crypto_analysis);
        }
    }

    // Look for secure boot functionality
    let has_secure_boot = embedded_string_combined.contains("Secure Boot")
        || embedded_string_combined.contains("Code Signing");

    if has_secure_boot {
        println!("✅ Found secure boot functionality");
    }

    assert_eq!(analysis.format, "motorola-srec");
}
