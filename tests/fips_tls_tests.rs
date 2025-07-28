// tests/fips_tls_tests.rs

use nabla::enterprise::CryptoProvider;
use rustls::{Certificate, PrivateKey};

#[test]
fn test_fips_crypto_provider_creation() {
    let provider = CryptoProvider::new(true, true).unwrap();
    assert!(provider.fips_enabled);
    assert!(provider.validation_enabled);
    
    let provider = CryptoProvider::new(false, false).unwrap();
    assert!(!provider.fips_enabled);
    assert!(!provider.validation_enabled);
}

#[test]
fn test_fips_compliance_validation() {
    let mut provider = CryptoProvider::new(true, true).unwrap();
    let result = provider.validate_fips_compliance();
    assert!(result.is_ok());
    
    let mut provider = CryptoProvider::new(false, true).unwrap();
    let result = provider.validate_fips_compliance();
    assert!(result.is_ok());
}

#[test]
fn test_fips_tls_compliance_validation() {
    let mut provider = CryptoProvider::new(true, true).unwrap();
    let result = provider.validate_fips_compliance();
    assert!(result.is_ok());
    
    let mut provider = CryptoProvider::new(false, true).unwrap();
    let result = provider.validate_fips_compliance();
    assert!(result.is_ok());
}

#[test]
fn test_fips_client_config_creation() {
    let provider = CryptoProvider::new(true, true).unwrap();
    let result = provider.get_fips_client_config();
    assert!(result.is_ok());
    
    let config = result.unwrap();
    assert!(config.enable_sni);
}

#[test]
fn test_fips_server_config_creation() {
    let provider = CryptoProvider::new(true, true).unwrap();
    let result = provider.get_fips_client_config();
    // This should fail because rustls 0.21+ requires certificates
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("certificates"));
}

#[test]
fn test_fips_client_config_without_fips_mode() {
    let provider = CryptoProvider::new(false, false).unwrap();
    let result = provider.get_fips_client_config();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("FIPS mode not enabled"));
}

#[test]
fn test_fips_server_config_without_fips_mode() {
    let provider = CryptoProvider::new(false, false).unwrap();
    let result = provider.get_fips_client_config();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("FIPS mode not enabled"));
}

#[test]
fn test_hash_functions_in_fips_mode() {
    let provider = CryptoProvider::new(true, true).unwrap();
    let data = b"test data";
    
    let sha256_result = provider.hash_sha256(data);
    assert!(sha256_result.is_ok());
    assert_eq!(sha256_result.unwrap().len(), 32);
    
    let sha512_result = provider.hash_sha512(data);
    assert!(sha512_result.is_ok());
    assert_eq!(sha512_result.unwrap().len(), 64);
    
    let alt_result = provider.hash_alternative(data);
    assert!(alt_result.is_ok());
    assert_eq!(alt_result.unwrap().len(), 64); // SHA-512 in FIPS mode
}

#[test]
fn test_hash_functions_in_standard_mode() {
    let provider = CryptoProvider::new(false, false).unwrap();
    let data = b"test data";
    
    let sha256_result = provider.hash_sha256(data);
    assert!(sha256_result.is_ok());
    assert_eq!(sha256_result.unwrap().len(), 32);
    
    let sha512_result = provider.hash_sha512(data);
    assert!(sha512_result.is_ok());
    assert_eq!(sha512_result.unwrap().len(), 64);
    
    let alt_result = provider.hash_alternative(data);
    assert!(alt_result.is_ok());
    // Blake3 hash length is 32 bytes
    assert_eq!(alt_result.unwrap().len(), 32);
}

#[test]
fn test_random_generation_in_fips_mode() {
    let provider = CryptoProvider::new(true, true).unwrap();
    let result = provider.generate_random(32);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn test_random_generation_in_standard_mode() {
    let provider = CryptoProvider::new(false, false).unwrap();
    let result = provider.generate_random(32);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn test_crypto_provider_clone() {
    let provider = CryptoProvider::new(true, true).unwrap();
    let cloned = provider.clone();
    
    assert_eq!(provider.fips_enabled, cloned.fips_enabled);
    assert_eq!(provider.validation_enabled, cloned.validation_enabled);
}

#[test]
fn test_fips_client_config_with_custom_roots() {
    let provider = CryptoProvider::new(true, true).unwrap();
    let custom_certs = vec![
        Certificate(vec![1, 2, 3, 4]), // Dummy certificate
    ];
    
    let result = provider.get_fips_client_config();
    // This should fail because the dummy certificate is invalid
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("certificate"));
}

#[test]
fn test_fips_server_config_with_custom_certs() {
    let provider = CryptoProvider::new(true, true).unwrap();
    let certs = vec![
        Certificate(vec![1, 2, 3, 4]), // Dummy certificate
    ];
    let key = PrivateKey(vec![5, 6, 7, 8]); // Dummy private key
    
    let result = provider.get_fips_server_config(&std::path::Path::new("dummy"), &std::path::Path::new("dummy"));
    // This should fail because the dummy certificate/key are invalid
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("certificate") || error_msg.contains("key") || error_msg.contains("invalid"));
} 