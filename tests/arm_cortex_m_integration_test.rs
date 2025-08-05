// Integration test for enhanced ARM Cortex-M firmware parsing
// This tests the actual analyze_binary function with real ARM Cortex-M firmware data

use nabla_cli::binary::analyze_binary;

use tokio;

/// Create a minimal ARM Cortex-M firmware blob for testing
fn create_test_cortex_m_firmware() -> Vec<u8> {
    let mut firmware_data = Vec::new();

    // ARM Cortex-M vector table (first 8 entries)
    // Stack pointer initial value
    firmware_data.extend_from_slice(&0x20002000u32.to_le_bytes());
    // Reset handler
    firmware_data.extend_from_slice(&0x08000101u32.to_le_bytes()); // Thumb bit set
    // NMI handler
    firmware_data.extend_from_slice(&0x08000201u32.to_le_bytes());
    // Hard fault handler
    firmware_data.extend_from_slice(&0x08000301u32.to_le_bytes());
    // Memory management fault
    firmware_data.extend_from_slice(&0x08000401u32.to_le_bytes());
    // Bus fault handler
    firmware_data.extend_from_slice(&0x08000501u32.to_le_bytes());
    // Usage fault handler
    firmware_data.extend_from_slice(&0x08000601u32.to_le_bytes());
    // Reserved
    firmware_data.extend_from_slice(&0x00000000u32.to_le_bytes());

    // Add more vector table entries (up to 64 common interrupts)
    for i in 0..56 {
        let handler_addr = 0x08000700u32 + (i * 0x10);
        firmware_data.extend_from_slice(&(handler_addr | 1).to_le_bytes()); // Thumb bit
    }

    // Add realistic ARM Cortex-M firmware strings
    let strings = [
        "ARM Cortex-M4 MCU",
        "STM32F407VGT6", // Popular Cortex-M4 microcontroller
        "Enhanced Security Module GRS.1",
        "FreeRTOS v10.4.3",
        "ARM CMSIS-RTOS2",
        "Hard Fault Handler",
        "SysTick_Handler",
        "PendSV_Handler",
        "SVC_Handler",
        "NVIC_SetPriority",
        "SystemInit",
        "__main",
        "Reset_Handler",
        "Default_Handler",
        "Flash_Write",
        "Flash_Erase",
        "UART_Init",
        "GPIO_Config",
        "Clock_Config",
        "Interrupt_Enable",
        "Task_Create",
        "Semaphore_Take",
        "Queue_Send",
        "Timer_Start",
        "ADC_Read",
        "PWM_SetDutyCycle",
        "CAN_Transmit",
        "I2C_Write",
        "SPI_Transfer",
        "DMA_Config",
    ];

    for s in strings.iter() {
        firmware_data.extend_from_slice(s.as_bytes());
        firmware_data.push(0); // Null terminator
    }

    // Add some ARM Thumb instructions (common patterns)
    let thumb_instructions = [
        0x4770, // bx lr (return)
        0xb500, // push {lr}
        0xbd00, // pop {pc}
        0x2000, // movs r0, #0
        0x4608, // mov r0, r1
        0x1c40, // adds r0, r0, #1
        0xd000, // beq label
        0xe7fe, // b . (infinite loop)
    ];

    for instr in thumb_instructions.iter() {
        firmware_data.extend_from_slice(&(*instr as u16).to_le_bytes());
    }

    // Pad to a reasonable firmware size
    while firmware_data.len() < 4096 {
        firmware_data.push(0);
    }

    firmware_data
}

/// Create ARM Cortex-M firmware with security features
fn create_secure_cortex_m_firmware() -> Vec<u8> {
    let mut firmware_data = Vec::new();

    // ARM Cortex-M vector table
    firmware_data.extend_from_slice(&0x20004000u32.to_le_bytes()); // Stack pointer
    firmware_data.extend_from_slice(&0x08000101u32.to_le_bytes()); // Reset handler

    // Fill out minimal vector table
    for _ in 0..30 {
        firmware_data.extend_from_slice(&0x08000201u32.to_le_bytes());
    }

    // Add security-related strings
    let security_strings = [
        "ARM TrustZone",
        "Secure World",
        "Non-Secure World",
        "PSA Certified",
        "Crypto Accelerator",
        "Hardware Security Module",
        "Root of Trust",
        "Secure Boot Loader",
        "Attestation Key",
        "Device Identity",
        "Firmware Integrity Check",
        "Anti-Tamper Protection",
        "Random Number Generator",
        "AES-256 Encryption",
        "SHA-256 Hash",
        "ECDSA Signature",
        "RSA-2048 Key",
        "Certificate Chain",
        "Secure Storage",
        "Key Derivation Function",
        "HMAC Authentication",
        "Secure Debug",
        "Code Protection",
        "Data Protection",
        "Secure Communication",
        "TLS 1.3 Protocol",
        "X.509 Certificate",
    ];

    for s in security_strings.iter() {
        firmware_data.extend_from_slice(s.as_bytes());
        firmware_data.push(0);
    }

    // Pad to size
    while firmware_data.len() < 2048 {
        firmware_data.push(0);
    }

    firmware_data
}

#[tokio::test]
async fn test_enhanced_cortex_m_firmware_parsing() {
    let firmware_data = create_test_cortex_m_firmware();

    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("cortex_firmware.bin", &firmware_data).await;

    assert!(
        result.is_ok(),
        "ARM Cortex-M firmware analysis should succeed"
    );

    let analysis = result.unwrap();

    // Verify basic detection
    assert_eq!(analysis.format, "arm-cortex-m-firmware");
    assert_eq!(analysis.file_name, "cortex_firmware.bin");
    assert!(analysis.size_bytes > 0);

    // Test ARM Cortex-M specific detection
    println!("Detected architecture: {}", analysis.architecture);
    println!("Format: {}", analysis.format);

    // Should detect ARM architecture
    assert!(
        analysis.architecture.contains("arm")
            || analysis.architecture.contains("cortex")
            || analysis.architecture.contains("thumb"),
        "Should detect ARM/Cortex architecture, got: {}",
        analysis.architecture
    );

    // Verify we extracted embedded strings
    assert!(
        !analysis.embedded_strings.is_empty(),
        "Should extract embedded strings"
    );

    let embedded_string_combined = analysis.embedded_strings.join(" ");
    println!("Embedded strings: {:?}", analysis.embedded_strings);

    // Look for ARM Cortex-M specific strings
    let has_cortex_strings = embedded_string_combined.contains("Cortex")
        || embedded_string_combined.contains("STM32")
        || embedded_string_combined.contains("Handler")
        || embedded_string_combined.contains("RTOS");

    assert!(
        has_cortex_strings,
        "Should find ARM Cortex-M specific strings in: {:?}",
        analysis.embedded_strings
    );

    // Check if ARM Cortex-M-specific metadata was added
    println!(
        "Metadata: {}",
        serde_json::to_string_pretty(&analysis.metadata).unwrap()
    );
}

#[tokio::test]
async fn test_cortex_m_vs_generic_arm() {
    let firmware_data = create_test_cortex_m_firmware();

    let analysis = analyze_binary("cortex_test.bin", &firmware_data)
        .await
        .expect("Analysis should succeed");

    // The key test: we should get specific ARM Cortex-M firmware detection
    println!("Architecture detected: '{}'", analysis.architecture);
    println!("Format: {}", analysis.format);
    println!(
        "Total embedded strings: {}",
        analysis.embedded_strings.len()
    );

    // Success criteria
    let success_checks = vec![
        (
            "ARM Cortex-M firmware format detected",
            analysis.format == "arm-cortex-m-firmware",
        ),
        (
            "ARM architecture detected",
            analysis.architecture.contains("arm") || analysis.architecture.contains("cortex"),
        ),
        (
            "Found embedded strings",
            !analysis.embedded_strings.is_empty(),
        ),
        ("Reasonable file size", analysis.size_bytes > 1000),
    ];

    for (check_name, passed) in success_checks {
        println!(
            "{}: {}",
            check_name,
            if passed { "✅ PASS" } else { "❌ FAIL" }
        );
    }

    // At minimum, we should detect it's ARM Cortex-M firmware
    assert_eq!(analysis.format, "arm-cortex-m-firmware");
}

#[tokio::test]
async fn test_secure_cortex_m_firmware() {
    let firmware_data = create_secure_cortex_m_firmware();

    let analysis = analyze_binary("secure_firmware.bin", &firmware_data)
        .await
        .expect("Analysis should succeed");

    // Look for security features
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_security_strings = embedded_string_combined.contains("TrustZone")
        || embedded_string_combined.contains("PSA")
        || embedded_string_combined.contains("Secure")
        || embedded_string_combined.contains("Crypto")
        || embedded_string_combined.contains("AES")
        || embedded_string_combined.contains("RSA");

    if has_security_strings {
        println!("✅ Found ARM security features");
    }

    // Look for ARM Cortex-M-specific analysis in metadata
    if let Some(cortex_analysis) = analysis.metadata.get("cortex_m_analysis") {
        println!("✅ Found Cortex-M-specific analysis: {}", cortex_analysis);
    } else if let Some(arm_analysis) = analysis.metadata.get("arm_analysis") {
        println!("✅ Found ARM-specific analysis: {}", arm_analysis);
    } else {
        println!("⚠️ No Cortex-M-specific analysis found, but basic parsing worked");
    }

    assert_eq!(analysis.format, "arm-cortex-m-firmware");

    // Check for security-related metadata
    if has_security_strings {
        // Could check for specific security metadata here
        println!("Security indicators found in firmware");
    }
}

#[tokio::test]
async fn test_cortex_m_rtos_detection() {
    let firmware_data = create_test_cortex_m_firmware();

    let analysis = analyze_binary("rtos_firmware.bin", &firmware_data)
        .await
        .expect("Analysis should succeed");

    // Look for RTOS functionality
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_rtos_strings = embedded_string_combined.contains("FreeRTOS")
        || embedded_string_combined.contains("RTOS")
        || embedded_string_combined.contains("Task")
        || embedded_string_combined.contains("Semaphore")
        || embedded_string_combined.contains("Queue");

    if has_rtos_strings {
        println!("✅ Found RTOS functionality indicators");
    }

    // Look for peripheral drivers
    let has_driver_strings = embedded_string_combined.contains("UART")
        || embedded_string_combined.contains("GPIO")
        || embedded_string_combined.contains("ADC")
        || embedded_string_combined.contains("PWM")
        || embedded_string_combined.contains("CAN")
        || embedded_string_combined.contains("I2C")
        || embedded_string_combined.contains("SPI");

    if has_driver_strings {
        println!("✅ Found peripheral driver functionality");
    }

    // Verify symbols were detected
    println!("Detected symbols: {:?}", analysis.detected_symbols);

    assert_eq!(analysis.format, "arm-cortex-m-firmware");
    assert!(
        has_rtos_strings || has_driver_strings,
        "Should find RTOS or driver functionality"
    );
}
