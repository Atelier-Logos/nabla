use nabla::enterprise::CryptoProvider;

#[test]
fn test_fips_initialization() {
    let mut crypto_provider = CryptoProvider::new(true, true);
    
    // Test FIPS initialization
    let result = crypto_provider.initialize();
    assert!(result.is_ok(), "FIPS initialization should succeed");
    
    // Verify FIPS mode is enabled
    assert!(crypto_provider.fips_mode);
    assert!(crypto_provider.module_initialized.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn test_fips_status() {
    let mut crypto_provider = CryptoProvider::new(true, true);
    crypto_provider.initialize().unwrap();
    
    let status = crypto_provider.get_fips_status();
    
    assert!(status.fips_enabled);
    assert!(status.module_initialized);
    assert!(status.entropy_validated);
    assert!(status.kdf_initialized);
    
    // Check that approved algorithms are listed
    assert!(status.approved_algorithms.contains(&"SHA-256".to_string()));
    assert!(status.approved_algorithms.contains(&"SHA-512".to_string()));
    assert!(status.approved_algorithms.contains(&"HMAC-SHA256".to_string()));
    assert!(status.approved_algorithms.contains(&"PBKDF2".to_string()));
    assert!(status.approved_algorithms.contains(&"HKDF".to_string()));
}

#[test]
fn test_key_derivation_pbkdf2() {
    let crypto_provider = CryptoProvider::new(true, true);
    
    let password = b"test_password";
    let salt = b"test_salt";
    let iterations = 10000;
    let key_len = 32;
    
    let derived_key = crypto_provider.derive_key_pbkdf2(password, salt, iterations, key_len);
    assert!(derived_key.is_ok());
    
    let key = derived_key.unwrap();
    assert_eq!(key.len(), key_len);
    
    // Verify the key is not all zeros
    assert!(!key.iter().all(|&b| b == 0));
}

#[test]
fn test_key_derivation_hkdf() {
    let crypto_provider = CryptoProvider::new(true, true);
    
    let secret = b"test_secret";
    let salt = b"test_salt";
    let info = b"test_info";
    let key_len = 32;
    
    let derived_key = crypto_provider.derive_key_hkdf(secret, salt, info, key_len);
    assert!(derived_key.is_ok());
    
    let key = derived_key.unwrap();
    assert_eq!(key.len(), key_len);
    
    // Verify the key is not all zeros
    assert!(!key.iter().all(|&b| b == 0));
}

#[test]
fn test_fips_requires_fips_mode() {
    let mut crypto_provider = CryptoProvider::new(false, false);
    
    // FIPS initialization should fail when FIPS mode is disabled
    let result = crypto_provider.initialize();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("FIPS mode must be enabled"));
}

#[test]
fn test_self_tests_integration() {
    let crypto_provider = CryptoProvider::new(true, true);
    
    // Test that hash functions work correctly
    let test_data = b"test_data";
    let hash_result = crypto_provider.hash_sha256(test_data);
    assert!(hash_result.is_ok());
    
    let hash = hash_result.unwrap();
    assert_eq!(hash.len(), 32);
    
    // Test random number generation
    let random_result = crypto_provider.generate_random(32);
    assert!(random_result.is_ok());
    
    let random_bytes = random_result.unwrap();
    assert_eq!(random_bytes.len(), 32);
}

#[test]
fn test_fips_serialization() {
    let mut crypto_provider = CryptoProvider::new(true, true);
    crypto_provider.initialize().unwrap();
    
    let status = crypto_provider.get_fips_status();
    
    // Test that the status can be serialized
    let json = serde_json::to_string(&status);
    assert!(json.is_ok());
    
    let json_str = json.unwrap();
    assert!(json_str.contains("fips_enabled"));
    assert!(json_str.contains("module_initialized"));
    assert!(json_str.contains("approved_algorithms"));
} 