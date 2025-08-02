// Integration test for enhanced compressed firmware parsing
// This tests the actual analyze_binary function with compressed firmware data

use nabla_cli::binary::analyze_binary;
use std::fs;
use tokio;

/// Create a gzip-compressed firmware blob for testing
fn create_gzip_compressed_firmware() -> Vec<u8> {
    let mut compressed_data = Vec::new();
    
    // Gzip header
    compressed_data.push(0x1f); // ID1
    compressed_data.push(0x8b); // ID2
    compressed_data.push(0x08); // Compression method (deflate)
    compressed_data.push(0x08); // Flags (FNAME set)
    
    // Timestamp (4 bytes, little endian)
    compressed_data.extend_from_slice(&1640995200u32.to_le_bytes());
    
    // Extra flags and OS
    compressed_data.push(0x00); // Extra flags
    compressed_data.push(0x03); // OS (Unix)
    
    // Original filename
    compressed_data.extend_from_slice(b"firmware.bin\0");
    
    // Compressed data (simplified deflate stream)
    // This represents compressed firmware content
    let fake_compressed_payload = [
        0x73, 0x2b, 0xca, 0x85, 0x68, 0x00, 0x82, 0xb4,
        0x41, 0x36, 0x06, 0x2e, 0x16, 0xce, 0x92, 0x4c,
        0x36, 0x85, 0xb4, 0x40, 0x00, 0xb2, 0xd4, 0xa2,
        0xd4, 0xe2, 0x12, 0x85, 0xf4, 0xdc, 0xd4, 0xe2,
        0x12, 0x2e, 0x06, 0x26, 0x16, 0x95, 0x68, 0x06,
        0x26, 0x56, 0x16, 0x95, 0x68, 0x81, 0x91, 0x95,
        0x87, 0x68, 0x06, 0x26, 0xd6, 0x70, 0x71, 0x0c,
        0x72, 0x71, 0x74, 0x71, 0x09, 0x01, 0x00
    ];
    
    compressed_data.extend_from_slice(&fake_compressed_payload);
    
    // CRC32 and original size (fake values)
    compressed_data.extend_from_slice(&0x12345678u32.to_le_bytes()); // CRC32
    compressed_data.extend_from_slice(&1024u32.to_le_bytes()); // Original size
    
    compressed_data
}

/// Create a compressed firmware with embedded strings
fn create_compressed_firmware_with_strings() -> Vec<u8> {
    let mut compressed_data = Vec::new();
    
    // LZ4 magic signature (alternative compression format)
    compressed_data.extend_from_slice(&[0x04, 0x22, 0x4d, 0x18]); // LZ4 magic
    
    // LZ4 frame descriptor
    compressed_data.push(0x64); // FLG
    compressed_data.push(0x40); // BD
    compressed_data.push(0x70); // HC (header checksum)
    
    // Block size
    compressed_data.extend_from_slice(&256u32.to_le_bytes());
    
    // Compressed content that would contain firmware strings
    let compressed_payload = b"Bootloader v2.1.0\x00Router Firmware\x00OpenWRT 21.02\x00Linux kernel 5.4.0\x00BusyBox v1.33.0\x00WiFi driver ath10k\x00Ethernet controller\x00Flash memory 16MB\x00RAM 128MB\x00CPU ARM Cortex-A7\x00Security module TPM 2.0\x00Encryption AES-256\x00Secure boot enabled\x00Certificate validation\x00Firmware signature OK";
    
    compressed_data.extend_from_slice(compressed_payload);
    
    // Block checksum
    compressed_data.extend_from_slice(&0xabcdef12u32.to_le_bytes());
    
    // End mark
    compressed_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    
    compressed_data
}

/// Create a compressed IoT device firmware
fn create_iot_compressed_firmware() -> Vec<u8> {
    let mut firmware_data = Vec::new();
    
    // Custom compression header (common in IoT devices)
    firmware_data.extend_from_slice(b"COMP"); // Magic
    firmware_data.extend_from_slice(&1u32.to_le_bytes()); // Version
    firmware_data.extend_from_slice(&0x1000u32.to_le_bytes()); // Original size
    firmware_data.extend_from_slice(&0x800u32.to_le_bytes()); // Compressed size
    firmware_data.extend_from_slice(&0x12345678u32.to_le_bytes()); // CRC
    
    // Device identification strings (would be compressed in real firmware)
    let iot_strings = [
        "ESP32-C3 WiFi Module",
        "IoT Device Manager v3.2",
        "Smart Home Controller",
        "Zigbee 3.0 Protocol Stack",
        "Matter/Thread Support",
        "OTA Update Manager",
        "Device Provisioning",
        "Cloud Connection Module",
        "Sensor Data Collection",
        "Actuator Control System",
        "Security Keys Manager",
        "Firmware Verification",
        "Factory Reset Handler",
        "Configuration Storage",
        "Network Stack TCP/IP",
        "HTTP/HTTPS Client",
        "MQTT Publisher/Subscriber",
        "CoAP Server Implementation",
        "JSON Parser Library",
        "Base64 Encoder/Decoder",
        "SHA-256 Hash Function",
        "AES Encryption Library",
        "Random Number Generator",
        "Watchdog Timer Service",
        "Power Management Unit"
    ];
    
    for s in iot_strings.iter() {
        firmware_data.extend_from_slice(s.as_bytes());
        firmware_data.push(0);
    }
    
    // Pad to expected compressed size
    while firmware_data.len() < 0x800 + 20 { // header size + compressed size
        firmware_data.push(0);
    }
    
    firmware_data
}

#[tokio::test]
async fn test_enhanced_compressed_firmware_parsing() {
    let firmware_data = create_gzip_compressed_firmware();
    
    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("firmware.gz", &firmware_data).await;
    
    assert!(result.is_ok(), "Compressed firmware analysis should succeed");
    
    let analysis = result.unwrap();
    
    // Verify basic detection
    assert_eq!(analysis.format, "compressed-firmware");
    assert_eq!(analysis.file_name, "firmware.gz");
    assert!(analysis.size_bytes > 0);
    
    // Test compressed firmware specific detection
    println!("Detected format: {}", analysis.format);
    println!("Detected architecture: {}", analysis.architecture);
    
    // Check if compressed firmware-specific metadata was added
    println!("Metadata: {}", serde_json::to_string_pretty(&analysis.metadata).unwrap());
}

#[tokio::test] 
async fn test_compressed_firmware_with_strings_parsing() {
    let firmware_data = create_compressed_firmware_with_strings();
    
    let analysis = analyze_binary("router_firmware.lz4", &firmware_data)
        .await
        .expect("Analysis should succeed");
    
    // The key test: we should get proper compressed firmware detection
    println!("Format detected: '{}'", analysis.format);
    println!("Architecture: {}", analysis.architecture);
    println!("Embedded strings: {:?}", analysis.embedded_strings);
    
    // Success criteria 
    let success_checks = vec![
        ("Compressed firmware format detected", analysis.format == "compressed-firmware"),
        ("Found embedded strings", !analysis.embedded_strings.is_empty()),
        ("File analyzed", analysis.size_bytes > 0),
    ];
    
    for (check_name, passed) in success_checks {
        println!("{}: {}", check_name, if passed { "✅ PASS" } else { "❌ FAIL" });
    }
    
    // Look for firmware-related strings
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_firmware_strings = embedded_string_combined.contains("Bootloader") ||
                              embedded_string_combined.contains("Firmware") ||
                              embedded_string_combined.contains("OpenWRT") ||
                              embedded_string_combined.contains("Linux") ||
                              embedded_string_combined.contains("BusyBox");
    
    if has_firmware_strings {
        println!("✅ Found firmware-specific strings");
    }
    
    // Should detect compressed firmware format
    assert_eq!(analysis.format, "compressed-firmware");
}

#[tokio::test]
async fn test_iot_compressed_firmware() {
    let firmware_data = create_iot_compressed_firmware();
    
    let analysis = analyze_binary("iot_device.bin", &firmware_data)
        .await
        .expect("Analysis should succeed");
    
    // Look for IoT-specific strings
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_iot_strings = embedded_string_combined.contains("ESP32") ||
                         embedded_string_combined.contains("IoT") ||
                         embedded_string_combined.contains("Smart Home") ||
                         embedded_string_combined.contains("Zigbee") ||
                         embedded_string_combined.contains("Matter") ||
                         embedded_string_combined.contains("Thread");
    
    if has_iot_strings {
        println!("✅ Found IoT device indicators");
    }
    
    // Look for networking protocols
    let has_network_strings = embedded_string_combined.contains("MQTT") ||
                             embedded_string_combined.contains("CoAP") ||
                             embedded_string_combined.contains("HTTP") ||
                             embedded_string_combined.contains("TCP/IP");
    
    if has_network_strings {
        println!("✅ Found networking protocol support");
    }
    
    // Look for security features
    let has_security_strings = embedded_string_combined.contains("AES") ||
                              embedded_string_combined.contains("SHA") ||
                              embedded_string_combined.contains("Security") ||
                              embedded_string_combined.contains("Verification");
    
    if has_security_strings {
        println!("✅ Found security functionality");
    }
    
    // Should detect as compressed firmware
    assert_eq!(analysis.format, "compressed-firmware");
    
    println!("IoT firmware analysis complete:");
    println!("  - Format: {}", analysis.format);
    println!("  - Architecture: {}", analysis.architecture);
    println!("  - Size: {} bytes", analysis.size_bytes);
}

#[tokio::test]
async fn test_compressed_firmware_metadata_extraction() {
    let firmware_data = create_iot_compressed_firmware();
    
    let analysis = analyze_binary("metadata_test.bin", &firmware_data)
        .await
        .expect("Analysis should succeed");
    
    // Look for compressed firmware-specific analysis in metadata
    if let Some(compressed_analysis) = analysis.metadata.get("compressed_firmware_analysis") {
        println!("✅ Found compressed firmware-specific analysis: {}", compressed_analysis);
    } else if let Some(firmware_analysis) = analysis.metadata.get("firmware_analysis") {
        println!("✅ Found firmware-specific analysis: {}", firmware_analysis);
    } else {
        println!("⚠️ No compressed firmware-specific analysis found, but basic parsing worked");
    }
    
    // Verify firmware features were detected
    println!("Languages: {:?}", analysis.languages);
    println!("Detected symbols: {:?}", analysis.detected_symbols);
    
    // Basic validation that we got a valid analysis
    assert_eq!(analysis.format, "compressed-firmware");
    assert!(analysis.size_bytes > 0);
}

#[tokio::test]
async fn test_compressed_firmware_vs_other_formats() {
    // Test with actual compressed firmware
    let firmware_data = create_gzip_compressed_firmware();
    let firmware_analysis = analyze_binary("real_firmware.gz", &firmware_data)
        .await
        .expect("Firmware analysis should succeed");
    
    // Test with regular gzip file (not firmware)
    let regular_gzip = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03document.txt\x00just some regular text content";
    let regular_analysis = analyze_binary("document.txt.gz", regular_gzip)
        .await
        .expect("Analysis should succeed");
    
    // Firmware should be detected as compressed firmware
    assert_eq!(firmware_analysis.format, "compressed-firmware");
    
    // Regular gzip might be detected differently
    println!("Firmware format: {}", firmware_analysis.format);
    println!("Regular gzip format: {}", regular_analysis.format);
    
    // At minimum, we should have distinguished them somehow
    // (either by format or by content analysis)
}

#[tokio::test]
async fn test_compressed_firmware_security_analysis() {
    let firmware_data = create_iot_compressed_firmware();
    
    let analysis = analyze_binary("security_firmware.bin", &firmware_data)
        .await
        .expect("Analysis should succeed");
    
    // Look for cryptographic functionality in the firmware
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_crypto_strings = embedded_string_combined.contains("AES") ||
                            embedded_string_combined.contains("SHA") ||
                            embedded_string_combined.contains("Random Number") ||
                            embedded_string_combined.contains("Encryption");
    
    if has_crypto_strings {
        println!("✅ Found cryptographic functionality indicators");
        
        // Check if this was flagged in metadata
        if let Some(crypto_analysis) = analysis.metadata.get("crypto_analysis") {
            println!("Crypto analysis: {}", crypto_analysis);
        }
    }
    
    // Look for OTA update capability (potential security vector)
    let has_ota_strings = embedded_string_combined.contains("OTA") ||
                         embedded_string_combined.contains("Update") ||
                         embedded_string_combined.contains("Cloud");
    
    if has_ota_strings {
        println!("✅ Found OTA/remote update functionality");
    }
    
    // Look for factory reset capability
    let has_reset_strings = embedded_string_combined.contains("Factory Reset") ||
                           embedded_string_combined.contains("Configuration");
    
    if has_reset_strings {
        println!("✅ Found factory reset functionality");
    }
    
    assert_eq!(analysis.format, "compressed-firmware");
}