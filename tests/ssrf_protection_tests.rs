use nabla::ssrf_protection::{SSRFValidator, SSRFConfig};

#[test]
fn test_whitelisted_domains() {
    let validator = SSRFValidator::new();
    
    // Test whitelisted domains
    assert!(validator.validate_url("https://api.openai.com/v1/chat/completions").is_ok());
    assert!(validator.validate_url("https://platform.atelierlogos.studio/marketplace/register").is_ok());
    assert!(validator.validate_url("https://aws.amazon.com/marketplace/listing").is_ok());
    assert!(validator.validate_url("https://api.together.xyz/v1/chat/completions").is_ok());
    assert!(validator.validate_url("https://huggingface.co/api/models").is_ok());
    
    // Test non-whitelisted domains
    assert!(validator.validate_url("https://evil.com/api").is_err());
    assert!(validator.validate_url("https://malicious.example.com/").is_err());
    assert!(validator.validate_url("https://attacker.com/steal-data").is_err());
}

#[test]
fn test_localhost_handling() {
    let mut validator = SSRFValidator::new();
    
    // Test localhost with allow_localhost = true (default)
    assert!(validator.validate_url("http://localhost:11434/completion").is_ok());
    assert!(validator.validate_url("http://127.0.0.1:8080/api").is_ok());
    assert!(validator.validate_url("http://localhost:3000/test").is_ok());
    
    // Test localhost with allow_localhost = false
    let mut config = validator.config().clone();
    config.allow_localhost = false;
    validator.update_config(config);
    assert!(validator.validate_url("http://localhost:11434/completion").is_err());
    assert!(validator.validate_url("http://127.0.0.1:8080/api").is_err());
    assert!(validator.validate_url("http://localhost:3000/test").is_err());
}

#[test]
fn test_private_ip_blocking() {
    let mut validator = SSRFValidator::new();
    
    // Test private IPs with allow_private_ips = false (default)
    assert!(validator.validate_url("http://192.168.1.1:8080/api").is_err());
    assert!(validator.validate_url("http://10.0.0.1:8080/api").is_err());
    assert!(validator.validate_url("http://172.16.0.1:8080/api").is_err());
    assert!(validator.validate_url("http://169.254.1.1:8080/api").is_err());
    
    // Test private IPs with allow_private_ips = true
    let mut config = validator.config().clone();
    config.allow_private_ips = true;
    validator.update_config(config);
    assert!(validator.validate_url("http://192.168.1.1:8080/api").is_ok());
    assert!(validator.validate_url("http://10.0.0.1:8080/api").is_ok());
    assert!(validator.validate_url("http://172.16.0.1:8080/api").is_ok());
    assert!(validator.validate_url("http://169.254.1.1:8080/api").is_ok());
}

#[test]
fn test_invalid_schemes() {
    let validator = SSRFValidator::new();
    
    // Test invalid schemes
    assert!(validator.validate_url("ftp://example.com").is_err());
    assert!(validator.validate_url("file:///etc/passwd").is_err());
    assert!(validator.validate_url("gopher://example.com").is_err());
    assert!(validator.validate_url("telnet://example.com").is_err());
    
    // Test valid schemes
    assert!(validator.validate_url("https://api.openai.com").is_ok());
    assert!(validator.validate_url("http://localhost:8080").is_ok());
}

#[test]
fn test_invalid_urls() {
    let validator = SSRFValidator::new();
    
    // Test invalid URLs
    assert!(validator.validate_url("not-a-url").is_err());
    assert!(validator.validate_url("http://").is_err());
    assert!(validator.validate_url("https://").is_err());
    assert!(validator.validate_url("").is_err());
}

#[test]
fn test_custom_whitelist() {
    let mut config = SSRFConfig::default();
    config.whitelisted_domains.insert("custom-api.com".to_string());
    config.whitelisted_domains.insert("my-service.org".to_string());
    
    let validator = SSRFValidator::with_config(config);
    
    // Test custom whitelisted domains
    assert!(validator.validate_url("https://custom-api.com/v1/endpoint").is_ok());
    assert!(validator.validate_url("https://my-service.org/api").is_ok());
    
    // Test that other domains are still blocked
    assert!(validator.validate_url("https://evil.com/api").is_err());
    assert!(validator.validate_url("https://malicious.org/").is_err());
}

#[test]
fn test_subdomain_handling() {
    let validator = SSRFValidator::new();
    
    // Test subdomains of whitelisted domains
    assert!(validator.validate_url("https://api.openai.com/v1/chat/completions").is_ok());
    assert!(validator.validate_url("https://beta.api.openai.com/v1/chat/completions").is_ok());
    assert!(validator.validate_url("https://us-east-1.api.openai.com/v1/chat/completions").is_ok());
    
    // Test that similar but different domains are blocked
    assert!(validator.validate_url("https://openai.evil.com/api").is_err());
    assert!(validator.validate_url("https://fake-openai.com/api").is_err());
}

#[test]
fn test_aws_marketplace_urls() {
    let validator = SSRFValidator::new();
    
    // Test AWS Marketplace URLs
    assert!(validator.validate_url("https://platform.atelierlogos.studio/marketplace/register?x-amzn-marketplace-token=ABC123").is_ok());
    assert!(validator.validate_url("https://aws.amazon.com/marketplace/your-listing-id").is_ok());
    assert!(validator.validate_url("https://marketplace.amazonaws.com/some-listing").is_ok());
}

#[test]
fn test_inference_server_urls() {
    let validator = SSRFValidator::new();
    
    // Test common inference server URLs
    assert!(validator.validate_url("http://localhost:11434/completion").is_ok());
    assert!(validator.validate_url("http://127.0.0.1:11434/completion").is_ok());
    assert!(validator.validate_url("https://api.openai.com/v1/chat/completions").is_ok());
    assert!(validator.validate_url("https://api.together.xyz/v1/chat/completions").is_ok());
    assert!(validator.validate_url("https://api.anthropic.com/v1/messages").is_ok());
    assert!(validator.validate_url("https://api.groq.com/openai/v1/chat/completions").is_ok());
}

#[test]
fn test_huggingface_urls() {
    let validator = SSRFValidator::new();
    
    // Test Hugging Face URLs
    assert!(validator.validate_url("https://huggingface.co/api/models").is_ok());
    assert!(validator.validate_url("https://hf-mirror.com/api/models").is_ok());
    assert!(validator.validate_url("https://huggingface.co/microsoft/DialoGPT-medium").is_ok());
}

#[test]
fn test_ssrf_attack_vectors() {
    let validator = SSRFValidator::new();
    
    // Test common SSRF attack vectors
    assert!(validator.validate_url("http://169.254.169.254/latest/meta-data/").is_err()); // AWS metadata
    assert!(validator.validate_url("http://169.254.169.254/latest/dynamic/instance-identity/document").is_err());
    assert!(validator.validate_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/").is_err());
    
    // Test other cloud metadata endpoints
    assert!(validator.validate_url("http://169.254.169.254/metadata/v1/").is_err()); // DigitalOcean
    assert!(validator.validate_url("http://169.254.169.254/metadata/instance").is_err()); // GCP
    assert!(validator.validate_url("http://169.254.169.254/metadata/instance/v1/").is_err()); // Azure
    
    // Test internal network access
    assert!(validator.validate_url("http://192.168.1.1/admin").is_err());
    assert!(validator.validate_url("http://10.0.0.1/config").is_err());
    assert!(validator.validate_url("http://172.16.0.1/api").is_err());
    
    // Test localhost with different ports
    assert!(validator.validate_url("http://localhost:22").is_err()); // SSH
    assert!(validator.validate_url("http://localhost:3306").is_err()); // MySQL
    assert!(validator.validate_url("http://localhost:5432").is_err()); // PostgreSQL
    assert!(validator.validate_url("http://localhost:6379").is_err()); // Redis
}

#[test]
fn test_url_manipulation_attempts() {
    let validator = SSRFValidator::new();
    
    // Test URL manipulation attempts
    assert!(validator.validate_url("https://api.openai.com@evil.com/api").is_err());
    assert!(validator.validate_url("https://api.openai.com#@evil.com/api").is_err());
    assert!(validator.validate_url("https://api.openai.com%00.evil.com/api").is_err());
    
    // Test encoding attempts
    assert!(validator.validate_url("https://api.openai.com%2Eevil.com/api").is_err());
    assert!(validator.validate_url("https://api.openai.com%00evil.com/api").is_err());
}

#[test]
fn test_configuration_management() {
    let mut validator = SSRFValidator::new();
    
    // Test adding domains to whitelist
    validator.add_whitelisted_domain("test-api.com".to_string());
    assert!(validator.validate_url("https://test-api.com/v1/endpoint").is_ok());
    
    // Test removing domains from whitelist
    validator.remove_whitelisted_domain("test-api.com");
    assert!(validator.validate_url("https://test-api.com/v1/endpoint").is_err());
    
    // Test adding IP ranges
    validator.add_whitelisted_ip("192.168.1.0/24".to_string());
    let mut config = validator.config().clone();
    config.allow_private_ips = false;
    validator.update_config(config);
    assert!(validator.validate_url("http://192.168.1.100:8080/api").is_ok());
    
    // Test removing IP ranges
    validator.remove_whitelisted_ip("192.168.1.0/24");
    assert!(validator.validate_url("http://192.168.1.100:8080/api").is_err());
} 