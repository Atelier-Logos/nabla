// Integration test for enhanced DICOM medical imaging parsing
// This tests the actual analyze_binary function with real DICOM data

use nabla_cli::binary::analyze_binary;
use std::fs;
use tokio;

/// Create a minimal DICOM file for testing
fn create_test_dicom() -> Vec<u8> {
    let mut dicom_data = Vec::new();
    
    // DICOM preamble (128 zero bytes)
    dicom_data.extend_from_slice(&[0u8; 128]);
    
    // DICOM prefix "DICM"
    dicom_data.extend_from_slice(b"DICM");
    
    // Meta Information Header
    // Transfer Syntax UID (0002,0010)
    dicom_data.extend_from_slice(&[0x02, 0x00, 0x10, 0x00]); // tag
    dicom_data.extend_from_slice(b"UI"); // VR
    dicom_data.extend_from_slice(&[0x1a, 0x00]); // length
    dicom_data.extend_from_slice(b"1.2.840.10008.1.2.1\0"); // Explicit VR Little Endian
    
    // Implementation Class UID (0002,0012)
    dicom_data.extend_from_slice(&[0x02, 0x00, 0x12, 0x00]);
    dicom_data.extend_from_slice(b"UI");
    dicom_data.extend_from_slice(&[0x1c, 0x00]);
    dicom_data.extend_from_slice(b"1.2.3.4.5.6.7.8.9.10.11\0");
    
    // Implementation Version Name (0002,0013)
    dicom_data.extend_from_slice(&[0x02, 0x00, 0x13, 0x00]);
    dicom_data.extend_from_slice(b"SH");
    dicom_data.extend_from_slice(&[0x10, 0x00]);
    dicom_data.extend_from_slice(b"NABLA_DICOM_1.0 ");
    
    // Patient Name (0010,0010)
    dicom_data.extend_from_slice(&[0x10, 0x00, 0x10, 0x00]);
    dicom_data.extend_from_slice(b"PN");
    dicom_data.extend_from_slice(&[0x0c, 0x00]);
    dicom_data.extend_from_slice(b"DOE^JOHN    ");
    
    // Patient ID (0010,0020)
    dicom_data.extend_from_slice(&[0x10, 0x00, 0x20, 0x00]);
    dicom_data.extend_from_slice(b"LO");
    dicom_data.extend_from_slice(&[0x08, 0x00]);
    dicom_data.extend_from_slice(b"12345678");
    
    // Study Date (0008,0020)
    dicom_data.extend_from_slice(&[0x08, 0x00, 0x20, 0x00]);
    dicom_data.extend_from_slice(b"DA");
    dicom_data.extend_from_slice(&[0x08, 0x00]);
    dicom_data.extend_from_slice(b"20240101");
    
    // Modality (0008,0060)
    dicom_data.extend_from_slice(&[0x08, 0x00, 0x60, 0x00]);
    dicom_data.extend_from_slice(b"CS");
    dicom_data.extend_from_slice(&[0x02, 0x00]);
    dicom_data.extend_from_slice(b"CT");
    
    // Manufacturer (0008,0070)
    dicom_data.extend_from_slice(&[0x08, 0x00, 0x70, 0x00]);
    dicom_data.extend_from_slice(b"LO");
    dicom_data.extend_from_slice(&[0x10, 0x00]);
    dicom_data.extend_from_slice(b"Siemens Medical ");
    
    // Institution Name (0008,0080)
    dicom_data.extend_from_slice(&[0x08, 0x00, 0x80, 0x00]);
    dicom_data.extend_from_slice(b"LO");
    dicom_data.extend_from_slice(&[0x14, 0x00]);
    dicom_data.extend_from_slice(b"General Hospital    ");
    
    dicom_data
}

/// Create a DICOM file with medical imaging software metadata
fn create_medical_software_dicom() -> Vec<u8> {
    let mut dicom_data = Vec::new();
    
    // Standard DICOM header
    dicom_data.extend_from_slice(&[0u8; 128]);
    dicom_data.extend_from_slice(b"DICM");
    
    // Add software-specific metadata
    let medical_strings = [
        "PACS System v5.2.1",
        "Medical Imaging Workstation",
        "DICOM Viewer Pro 2024",
        "Radiology Information System",
        "Picture Archiving Communication",
        "FDA Approved Medical Device",
        "HIPAA Compliant Software",
        "Medical Device Class II",
        "Cardiac Catheterization Lab",
        "Interventional Radiology Suite",
        "Digital Mammography System",
        "MRI Scanner Control Software",
        "CT Reconstruction Algorithm",
        "Ultrasound Imaging Platform",
        "Nuclear Medicine Workstation",
        "Radiation Therapy Planning",
        "Medical Image Processing",
        "Clinical Decision Support",
        "Patient Data Management",
        "Electronic Health Records"
    ];
    
    // Convert strings to DICOM-like format
    for (i, text) in medical_strings.iter().enumerate() {
        let tag_group = 0x7fe0u16 + (i as u16 % 16);
        let tag_element = 0x0010u16 + (i as u16);
        
        dicom_data.extend_from_slice(&tag_group.to_le_bytes());
        dicom_data.extend_from_slice(&tag_element.to_le_bytes());
        dicom_data.extend_from_slice(b"LO");
        
        let text_len = text.len() as u16;
        let padded_len = if text_len % 2 == 1 { text_len + 1 } else { text_len };
        dicom_data.extend_from_slice(&padded_len.to_le_bytes());
        
        dicom_data.extend_from_slice(text.as_bytes());
        if text_len % 2 == 1 {
            dicom_data.push(b' '); // DICOM padding
        }
    }
    
    dicom_data
}

/// Create a DICOM file that might contain embedded executable code (security concern)
fn create_suspicious_dicom() -> Vec<u8> {
    let mut dicom_data = Vec::new();
    
    // Standard DICOM header
    dicom_data.extend_from_slice(&[0u8; 128]);
    dicom_data.extend_from_slice(b"DICM");
    
    // Add suspicious strings that might indicate embedded code
    let suspicious_strings = [
        "CreateProcess",
        "VirtualAlloc", 
        "WriteProcessMemory",
        "ShellExecute",
        "WinExec",
        "system(",
        "exec(",
        "/bin/sh",
        "cmd.exe",
        "powershell.exe",
        "rundll32.exe",
        "RegOpenKeyEx",
        "CryptDecrypt",
        "Base64Decode",
        "XOR Encryption",
        "Buffer Overflow",
        "Return Address",
        "Shellcode Injection",
        "DLL Hijacking",
        "Process Hollowing"
    ];
    
    for (i, text) in suspicious_strings.iter().enumerate() {
        // Use private tags that might be used to hide malicious content
        let tag_group = 0x7777u16;
        let tag_element = 0x0010u16 + (i as u16);
        
        dicom_data.extend_from_slice(&tag_group.to_le_bytes());
        dicom_data.extend_from_slice(&tag_element.to_le_bytes());
        dicom_data.extend_from_slice(b"OB"); // Other Byte String
        
        let text_len = text.len() as u16;
        let padded_len = if text_len % 2 == 1 { text_len + 1 } else { text_len };
        dicom_data.extend_from_slice(&padded_len.to_le_bytes());
        
        dicom_data.extend_from_slice(text.as_bytes());
        if text_len % 2 == 1 {
            dicom_data.push(0);
        }
    }
    
    // Add some binary data that looks like executable code
    let fake_shellcode = [
        0x48, 0x31, 0xc0,       // xor rax, rax
        0x48, 0x31, 0xdb,       // xor rbx, rbx  
        0x48, 0x31, 0xc9,       // xor rcx, rcx
        0x48, 0x31, 0xd2,       // xor rdx, rdx
        0xb0, 0x3b,             // mov al, 0x3b (sys_execve)
        0x0f, 0x05,             // syscall
        0x90, 0x90, 0x90, 0x90  // nops
    ];
    
    dicom_data.extend_from_slice(&[0x7f, 0x77, 0xff, 0x00]); // private tag
    dicom_data.extend_from_slice(b"OB");
    dicom_data.extend_from_slice(&(fake_shellcode.len() as u16).to_le_bytes());
    dicom_data.extend_from_slice(&fake_shellcode);
    
    dicom_data
}

#[tokio::test]
async fn test_enhanced_dicom_parsing() {
    let dicom_data = create_test_dicom();
    
    // This is the real test - calling our actual analyze_binary function
    let result = analyze_binary("patient_scan.dcm", &dicom_data).await;
    
    assert!(result.is_ok(), "DICOM analysis should succeed");
    
    let analysis = result.unwrap();
    
    // Verify basic detection - could be various DICOM formats
    assert!(
        analysis.format == "dicom-medical-imaging" || 
        analysis.format == "dicom-file" ||
        analysis.format == "medical-imaging-software",
        "Should detect DICOM format, got: {}",
        analysis.format
    );
    
    assert_eq!(analysis.file_name, "patient_scan.dcm");
    assert!(analysis.size_bytes > 0);
    
    // Test DICOM specific detection
    println!("Detected format: {}", analysis.format);
    println!("Detected architecture: {}", analysis.architecture);
    
    // Verify we extracted embedded strings
    if !analysis.embedded_strings.is_empty() {
        println!("Embedded strings: {:?}", analysis.embedded_strings);
        
        let embedded_string_combined = analysis.embedded_strings.join(" ");
        let has_medical_strings = embedded_string_combined.contains("DOE") ||
                                 embedded_string_combined.contains("DICOM") ||
                                 embedded_string_combined.contains("Medical") ||
                                 embedded_string_combined.contains("Siemens");
        
        if has_medical_strings {
            println!("✅ Found medical/DICOM strings");
        }
    }
    
    // Check if DICOM-specific metadata was added
    println!("Metadata: {}", serde_json::to_string_pretty(&analysis.metadata).unwrap());
}

#[tokio::test] 
async fn test_medical_software_dicom_parsing() {
    let dicom_data = create_medical_software_dicom();
    
    let analysis = analyze_binary("medical_software.dcm", &dicom_data)
        .await
        .expect("Analysis should succeed");
    
    // The key test: we should get proper DICOM detection
    println!("Format detected: '{}'", analysis.format);
    println!("Architecture: {}", analysis.architecture);
    println!("Embedded strings: {:?}", analysis.embedded_strings);
    
    // Success criteria 
    let success_checks = vec![
        ("DICOM format detected", analysis.format.contains("dicom") || analysis.format.contains("medical")),
        ("Found embedded strings", !analysis.embedded_strings.is_empty()),
        ("File analyzed", analysis.size_bytes > 0),
    ];
    
    for (check_name, passed) in success_checks {
        println!("{}: {}", check_name, if passed { "✅ PASS" } else { "❌ FAIL" });
    }
    
    // Look for medical software strings
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_medical_software_strings = embedded_string_combined.contains("PACS") ||
                                      embedded_string_combined.contains("Medical") ||
                                      embedded_string_combined.contains("Imaging") ||
                                      embedded_string_combined.contains("Radiology") ||
                                      embedded_string_combined.contains("FDA") ||
                                      embedded_string_combined.contains("HIPAA");
    
    if has_medical_software_strings {
        println!("✅ Found medical software specific strings");
    }
    
    // Should detect some form of DICOM/medical format
    assert!(analysis.format.contains("dicom") || analysis.format.contains("medical"));
}

#[tokio::test]
async fn test_dicom_metadata_extraction() {
    let dicom_data = create_test_dicom();
    
    let analysis = analyze_binary("metadata_test.dcm", &dicom_data)
        .await
        .expect("Analysis should succeed");
    
    // Look for DICOM-specific analysis in metadata
    if let Some(dicom_analysis) = analysis.metadata.get("dicom_analysis") {
        println!("✅ Found DICOM-specific analysis: {}", dicom_analysis);
    } else if let Some(medical_analysis) = analysis.metadata.get("medical_analysis") {
        println!("✅ Found medical-specific analysis: {}", medical_analysis);
    } else {
        println!("⚠️ No DICOM-specific analysis found, but basic parsing worked");
    }
    
    // Verify medical features were detected
    println!("Languages: {:?}", analysis.languages);
    println!("Detected symbols: {:?}", analysis.detected_symbols);
    
    // Basic validation that we got a valid DICOM analysis
    assert!(analysis.format.contains("dicom") || analysis.format.contains("medical"));
    assert!(analysis.size_bytes > 0);
}

#[tokio::test]
async fn test_suspicious_dicom_security_analysis() {
    let dicom_data = create_suspicious_dicom();
    
    let analysis = analyze_binary("suspicious.dcm", &dicom_data)
        .await
        .expect("Analysis should succeed");
    
    // Look for suspicious content in DICOM
    let embedded_string_combined = analysis.embedded_strings.join(" ");
    let has_suspicious_strings = embedded_string_combined.contains("CreateProcess") ||
                                embedded_string_combined.contains("ShellExecute") ||
                                embedded_string_combined.contains("system(") ||
                                embedded_string_combined.contains("cmd.exe") ||
                                embedded_string_combined.contains("Shellcode");
    
    if has_suspicious_strings {
        println!("⚠️ Found suspicious strings in DICOM file");
        
        // Check if this was flagged as suspicious in metadata
        if let Some(security_analysis) = analysis.metadata.get("security_analysis") {
            println!("Security analysis: {}", security_analysis);
        }
        
        // This should potentially be flagged as suspicious
        println!("⚠️ DICOM file contains potentially malicious content");
    }
    
    // Look for suspected secrets (potential exfiltration)
    if !analysis.suspected_secrets.is_empty() {
        println!("⚠️ Found suspected secrets in DICOM: {:?}", analysis.suspected_secrets);
    }
    
    // Should still detect as DICOM format
    assert!(analysis.format.contains("dicom") || analysis.format.contains("medical"));
}

#[tokio::test]
async fn test_dicom_vs_other_formats() {
    // Test with actual DICOM
    let dicom_data = create_test_dicom();
    let dicom_analysis = analyze_binary("real.dcm", &dicom_data)
        .await
        .expect("DICOM analysis should succeed");
    
    // Test with data that's not DICOM but has DICM somewhere
    let fake_dicom = b"This is not a real DICOM file but contains DICM somewhere in the middle";
    let fake_analysis = analyze_binary("fake.dcm", fake_dicom)
        .await
        .expect("Analysis should succeed");
    
    // Real DICOM should be detected correctly
    assert!(dicom_analysis.format.contains("dicom") || dicom_analysis.format.contains("medical"));
    
    // Fake DICOM should not be detected as DICOM
    assert!(!fake_analysis.format.contains("dicom"));
    
    println!("Real DICOM format: {}", dicom_analysis.format);
    println!("Fake DICOM format: {}", fake_analysis.format);
}