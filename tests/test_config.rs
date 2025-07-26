use std::env;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn setup_test_environment() {
    INIT.call_once(|| {
        // Set up test environment variables if not already set
        if env::var("LICENSE_SIGNING_KEY").is_err() {
            // Use a test key for testing - 32 bytes encoded in URL-safe base64 without padding
            env::set_var("LICENSE_SIGNING_KEY", "dGVzdC1rZXktZm9yLXRlc3RpbmctcHVycG9zZXMtb25seS0zMg");
        }
        
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "error");
        }
    });
}

pub fn get_test_license_key() -> String {
    env::var("LICENSE_SIGNING_KEY").unwrap_or_else(|_| {
        "dGVzdC1rZXktZm9yLXRlc3RpbmctcHVycG9zZXMtb25seS0zMg".to_string()
    })
}

pub fn create_test_binary_data() -> Vec<u8> {
    // Create a minimal ELF binary for testing
    let mut data = vec![
        0x7f, 0x45, 0x4c, 0x46, // ELF magic
        0x02,                     // 64-bit
        0x01,                     // Little endian
        0x01,                     // ELF version
        0x00,                     // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x03, 0x00,              // ET_DYN
        0x3e, 0x00,              // x86-64
        0x01, 0x00, 0x00, 0x00,  // ELF version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Flags
        0x40, 0x00,              // ELF header size
        0x38, 0x00,              // Program header entry size
        0x01, 0x00,              // Program header count
        0x40, 0x00,              // Section header entry size
        0x03, 0x00,              // Section header count
        0x02, 0x00,              // Section name string table index
    ];
    
    // Add some additional data to make it look more realistic
    data.extend_from_slice(&vec![0x00; 100]);
    data
}

pub fn create_test_multipart_data(filename: &str, content: &[u8]) -> String {
    format!(
        "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n{}\r\n--boundary--",
        filename,
        String::from_utf8_lossy(content)
    )
} 