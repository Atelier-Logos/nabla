use std::process::Command;
use std::env;
use tempfile::TempDir;
use std::fs;
mod test_config;
use test_config::setup_test_environment;

#[test]
fn test_mint_license_basic() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "mint_license", "--", "--sub", "test-company", "--trial-14"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute mint_license");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let token = binding.trim();
    assert!(!token.is_empty());
    assert!(token.contains('.'));
}

#[test]
fn test_mint_license_all_expiry_options() {
    setup_test_environment();
    let expiry_options = [
        ("--trial-14", "14-day trial"),
        ("--trial-30", "30-day trial"),
        ("--quarterly", "3-month"),
        ("--annual", "12-month"),
        ("--three-year", "3-year"),
    ];
    
    for (flag, description) in expiry_options {
        let output = Command::new("cargo")
            .args(["run", "--bin", "mint_license", "--", "--sub", "test-company", flag])
            .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
            .output()
            .expect(&format!("Failed to execute mint_license with {}", description));
        
        assert!(output.status.success(), "Failed for {}", description);
        let binding = String::from_utf8_lossy(&output.stdout);
        let token = binding.trim();
        assert!(!token.is_empty());
    }
}

#[test]
fn test_mint_license_with_deployment_id() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args([
            "run", "--bin", "mint_license", "--",
            "--sub", "test-company",
            "--deployment-id", "12345678-1234-1234-1234-123456789abc",
            "--trial-14"
        ])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute mint_license with deployment_id");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let token = binding.trim();
    assert!(!token.is_empty());
}

#[test]
fn test_mint_license_with_custom_plan() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args([
            "run", "--bin", "mint_license", "--",
            "--sub", "test-company",
            "--plan", "premium",
            "--trial-14"
        ])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute mint_license with custom plan");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let token = binding.trim();
    assert!(!token.is_empty());
}

#[test]
fn test_mint_license_with_custom_rate_limit() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args([
            "run", "--bin", "mint_license", "--",
            "--sub", "test-company",
            "--rate-limit", "100",
            "--trial-14"
        ])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute mint_license with custom rate limit");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let token = binding.trim();
    assert!(!token.is_empty());
}

#[test]
fn test_mint_license_missing_required_args() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "mint_license", "--", "--sub", "test-company"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute mint_license without expiry");
    
    // Should fail because no expiry option is provided
    assert!(!output.status.success());
}

#[test]
fn test_mint_license_missing_env_var() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "mint_license", "--", "--sub", "test-company", "--trial_14"])
        .output()
        .expect("Failed to execute mint_license without env var");
    
    // Should fail because LICENSE_SIGNING_KEY is not set
    assert!(!output.status.success());
}

#[test]
fn test_jwt_validation_test_valid_token() {
    setup_test_environment();
    let secret = env::var("LICENSE_SIGNING_KEY").unwrap();
    
    // First create a valid token
    let token_output = Command::new("cargo")
        .args(["run", "--bin", "mint_license", "--", "--sub", "test-company", "--trial-14"])
        .env("LICENSE_SIGNING_KEY", &secret)
        .output()
        .expect("Failed to create test token");
    
    assert!(token_output.status.success());
    let binding = String::from_utf8_lossy(&token_output.stdout);
    let token = binding.trim();
    
    // Now test the token with the same secret
    let output = Command::new("cargo")
        .args(["run", "--bin", "jwt_validation_test", "--", "--token", &token, "--secret", &secret])
        .output()
        .expect("Failed to execute jwt_validation_test");
    
    assert!(output.status.success());
}

#[test]
fn test_jwt_validation_test_invalid_token() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "jwt_validation_test", "--", "--token", "invalid.token.here"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute jwt_validation_test with invalid token");
    
    // Should fail because token is invalid
    assert!(!output.status.success());
}

#[test]
fn test_jwt_validation_test_missing_token() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "jwt_validation_test", "--"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute jwt_validation_test without token");
    
    // Should fail because no token provided
    assert!(!output.status.success());
}

#[test]
fn test_generate_hmac_basic() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "generate_hmac", "--", "--message", "test message"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute generate_hmac");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let hmac = binding.trim();
    assert!(!hmac.is_empty());
}

#[test]
fn test_generate_hmac_empty_message() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "generate_hmac", "--", "--message", ""])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute generate_hmac with empty message");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let hmac = binding.trim();
    assert!(!hmac.is_empty());
}

#[test]
fn test_generate_hmac_special_characters() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "generate_hmac", "--", "--message", "test@#$%^&*()_+{}|:<>?[]\\;'\",./<>?"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute generate_hmac with special characters");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let hmac = binding.trim();
    assert!(!hmac.is_empty());
}

#[test]
fn test_generate_hmac_missing_message() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "generate_hmac", "--"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute generate_hmac without message");
    
    // Should fail because no message provided
    assert!(!output.status.success());
}

#[test]
fn test_generate_hmac_missing_env_var() {
    // Don't call setup_test_environment() - we want to test missing env var
    // Explicitly unset the environment variable
    let output = Command::new("cargo")
        .args(["run", "--bin", "generate_hmac", "--", "--message", "test message"])
        .env_remove("LICENSE_SIGNING_KEY")
        .output()
        .expect("Failed to execute generate_hmac without env var");
    
    // Should fail because LICENSE_SIGNING_KEY is not set
    assert!(!output.status.success());
}

#[test]
fn test_cli_tools_help() {
    setup_test_environment();
    let tools = ["mint_license", "jwt_validation_test", "generate_hmac"];
    
    for tool in tools {
        let output = Command::new("cargo")
            .args(["run", "--bin", tool, "--", "--help"])
            .output()
            .expect(&format!("Failed to execute {} --help", tool));
        
        // Help should always succeed
        assert!(output.status.success());
        let help_text = String::from_utf8_lossy(&output.stdout);
        assert!(help_text.contains("Usage:"));
    }
}

#[test]
fn test_cli_tools_version() {
    setup_test_environment();
    let tools = ["mint_license", "jwt_validation_test", "generate_hmac"];
    
    for tool in tools {
        let output = Command::new("cargo")
            .args(["run", "--bin", tool, "--", "--version"])
            .output()
            .expect(&format!("Failed to execute {} --version", tool));
        
        // Version should always succeed
        assert!(output.status.success());
        let version_text = String::from_utf8_lossy(&output.stdout);
        // Check for version number format (e.g., "mint_license 0.1.0")
        assert!(version_text.contains("0.1.0"));
    }
}

#[test]
fn test_cli_tools_invalid_args() {
    setup_test_environment();
    let output = Command::new("cargo")
        .args(["run", "--bin", "mint_license", "--", "--invalid-arg"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute mint_license with invalid args");
    
    // Should fail because of invalid argument
    assert!(!output.status.success());
}

#[test]
fn test_cli_tools_file_output() {
    setup_test_environment();
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("license.txt");
    
    // Test redirecting output to file
    let output = Command::new("cargo")
        .args(["run", "--bin", "mint_license", "--", "--sub", "test-company", "--trial-14"])
        .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
        .stdout(std::process::Stdio::from(
            fs::File::create(&output_file).unwrap()
        ))
        .output()
        .expect("Failed to execute mint_license with file output");
    
    assert!(output.status.success());
    assert!(output_file.exists());
    
    let content = fs::read_to_string(&output_file).unwrap();
    assert!(!content.is_empty());
}

#[test]
fn test_cli_tools_concurrent_execution() {
    setup_test_environment();
    use std::thread;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];
    
    for i in 0..5 {
        let success_count = Arc::clone(&success_count);
        let handle = thread::spawn(move || {
            let output = Command::new("cargo")
                .args([
                    "run", "--bin", "mint_license", "--",
                    "--sub", &format!("test-company-{}", i),
                    "--trial-14"
                ])
                .env("LICENSE_SIGNING_KEY", env::var("LICENSE_SIGNING_KEY").unwrap())
                .output();
            
            if output.is_ok() && output.unwrap().status.success() {
                success_count.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // All concurrent executions should succeed
    assert_eq!(success_count.load(Ordering::SeqCst), 5);
} 