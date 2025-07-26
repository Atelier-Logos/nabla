// tests/config_tests.rs

use nabla::config::Config;
use std::env;

#[test]
fn test_config_from_env_default() {
    // Clear any existing env vars
    env::remove_var("PORT");
    env::remove_var("BASE_URL");
    
    let config = Config::from_env();
    assert!(config.is_ok());
    
    let config = config.unwrap();
    assert_eq!(config.port, 8080); // Default port
    assert_eq!(config.base_url, "http://localhost:8080"); // Default base_url
}

#[test]
fn test_config_from_env_custom_port() {
    // Clear any existing env vars first
    env::remove_var("PORT");
    env::remove_var("BASE_URL");
    
    // Set custom port
    env::set_var("PORT", "9090");
    
    let config = Config::from_env();
    assert!(config.is_ok());
    
    let config = config.unwrap();
    assert_eq!(config.port, 9090);
    
    // Clean up
    env::remove_var("PORT");
}

#[test]
fn test_config_from_env_custom_base_url() {
    // Clear any existing env vars first
    env::remove_var("PORT");
    env::remove_var("BASE_URL");
    
    // Set custom base_url
    env::set_var("BASE_URL", "https://api.example.com");
    
    let config = Config::from_env();
    assert!(config.is_ok());
    
    let config = config.unwrap();
    assert_eq!(config.base_url, "https://api.example.com");
    
    // Clean up
    env::remove_var("BASE_URL");
}

#[test]
fn test_config_from_env_invalid_port() {
    // Set invalid port
    env::set_var("PORT", "invalid");
    
    let config = Config::from_env();
    assert!(config.is_err());
    
    // Clean up
    env::remove_var("PORT");
}

#[test]
fn test_config_from_env_very_large_port() {
    // Set port that's too large
    env::set_var("PORT", "99999");
    
    let config = Config::from_env();
    assert!(config.is_err());
    
    // Clean up
    env::remove_var("PORT");
}

#[test]
fn test_config_from_env_zero_port() {
    // Set zero port
    env::set_var("PORT", "0");
    
    let config = Config::from_env();
    // Note: u16::from_str("0") actually succeeds, so this should be ok
    assert!(config.is_ok());
    
    // Clean up
    env::remove_var("PORT");
}

#[test]
fn test_config_from_env_negative_port() {
    // Set negative port
    env::set_var("PORT", "-1");
    
    let config = Config::from_env();
    assert!(config.is_err());
    
    // Clean up
    env::remove_var("PORT");
}

#[test]
fn test_config_serialization() {
    let config = Config { 
        port: 8080,
        base_url: "http://localhost:8080".to_string(),
    };
    
    // Test that we can access the fields
    assert_eq!(config.port, 8080);
    assert_eq!(config.base_url, "http://localhost:8080");
}

#[test]
fn test_config_debug() {
    let config = Config { 
        port: 8080,
        base_url: "http://localhost:8080".to_string(),
    };
    let debug_str = format!("{:?}", config);
    
    assert!(debug_str.contains("8080"));
    assert!(debug_str.contains("Config"));
    assert!(debug_str.contains("http://localhost:8080"));
}

#[test]
fn test_config_clone() {
    let config = Config { 
        port: 8080,
        base_url: "http://localhost:8080".to_string(),
    };
    let cloned_config = config.clone();
    
    assert_eq!(config.port, cloned_config.port);
    assert_eq!(config.base_url, cloned_config.base_url);
    assert_eq!(config.port, 8080);
} 