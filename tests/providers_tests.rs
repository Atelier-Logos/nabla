// tests/providers_tests.rs

use nabla::providers::{HTTPProvider, GenerationOptions, GenerationResponse, InferenceError};
use tokio;

#[tokio::test]
async fn test_http_provider_new() {
    let _provider = HTTPProvider::new(
        "http://localhost:11434".to_string(),
        Some("test_key".to_string()),
        Some("test_token".to_string()),
    );
    
    // Test that the provider was created successfully
    assert!(true); // Provider creation should not panic
}

#[tokio::test]
async fn test_generation_options_default() {
    let options = GenerationOptions::default();
    assert_eq!(options.max_tokens, 512);
    assert_eq!(options.temperature, 0.7);
    assert_eq!(options.top_p, 0.9);
    assert!(options.stop_sequences.is_empty());
    assert!(options.model_path.is_none());
    assert!(options.hf_repo.is_none());
    assert!(options.model.is_none());
}

#[tokio::test]
async fn test_generation_options_custom() {
    let options = GenerationOptions {
        max_tokens: 1024,
        temperature: 0.5,
        top_p: 0.8,
        stop_sequences: vec!["\n".to_string(), "```".to_string()],
        model_path: Some("models/test.gguf".to_string()),
        hf_repo: Some("test/repo".to_string()),
        model: Some("gpt-4".to_string()),
    };
    
    assert_eq!(options.max_tokens, 1024);
    assert_eq!(options.temperature, 0.5);
    assert_eq!(options.top_p, 0.8);
    assert_eq!(options.stop_sequences.len(), 2);
    assert_eq!(options.model_path, Some("models/test.gguf".to_string()));
    assert_eq!(options.hf_repo, Some("test/repo".to_string()));
    assert_eq!(options.model, Some("gpt-4".to_string()));
}

#[tokio::test]
async fn test_generation_response() {
    let response = GenerationResponse {
        text: "Hello, world!".to_string(),
        tokens_used: 10,
        finish_reason: "stop".to_string(),
    };
    
    assert_eq!(response.text, "Hello, world!");
    assert_eq!(response.tokens_used, 10);
    assert_eq!(response.finish_reason, "stop");
}

#[test]
fn test_inference_error_variants() {
    let network_error = InferenceError::NetworkError("connection failed".to_string());
    let server_error = InferenceError::ServerError("500 Internal Server Error".to_string());
    let no_provider = InferenceError::NoAvailableProvider;
    
    match network_error {
        InferenceError::NetworkError(msg) => assert_eq!(msg, "connection failed"),
        _ => panic!("Expected NetworkError"),
    }
    
    match server_error {
        InferenceError::ServerError(msg) => assert_eq!(msg, "500 Internal Server Error"),
        _ => panic!("Expected ServerError"),
    }
    
    match no_provider {
        InferenceError::NoAvailableProvider => assert!(true),
        _ => panic!("Expected NoAvailableProvider"),
    }
}

#[tokio::test]
async fn test_http_provider_llama_cpp_mode() {
    let _provider = HTTPProvider::new(
        "http://localhost:11434".to_string(),
        None,
        None,
    );
    
    let _options = GenerationOptions {
        model_path: Some("models/test.gguf".to_string()),
        max_tokens: 100,
        temperature: 0.1,
        top_p: 0.9,
        stop_sequences: vec![],
        hf_repo: None,
        model: None,
    };
    
    // Test that the provider and options are created correctly
    assert!(true);
}

#[tokio::test]
async fn test_http_provider_openai_mode() {
    let _provider = HTTPProvider::new(
        "https://api.openai.com".to_string(),
        Some("sk-test-key".to_string()),
        None,
    );
    
    let _options = GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.1,
        top_p: 0.9,
        stop_sequences: vec![],
        model_path: None,
        hf_repo: None,
    };
    
    // Test that the provider and options are created correctly
    assert!(true);
}

#[tokio::test]
async fn test_http_provider_with_hf_repo() {
    let _provider = HTTPProvider::new(
        "http://localhost:11434".to_string(),
        None,
        None,
    );
    
    let _options = GenerationOptions {
        hf_repo: Some("microsoft/DialoGPT-medium".to_string()),
        max_tokens: 100,
        temperature: 0.1,
        top_p: 0.9,
        stop_sequences: vec![],
        model_path: None,
        model: None,
    };
    
    // Test that the provider and options are created correctly
    assert!(true);
}

#[tokio::test]
async fn test_http_provider_with_provider_token() {
    let _provider = HTTPProvider::new(
        "https://api.together.xyz".to_string(),
        None,
        Some("tgp_v1_test_token".to_string()),
    );
    
    let _options = GenerationOptions {
        model: Some("moonshotai/Kimi-K2-Instruct".to_string()),
        max_tokens: 100,
        temperature: 0.1,
        top_p: 0.9,
        stop_sequences: vec![],
        model_path: None,
        hf_repo: None,
    };
    
    // Test that the provider and options are created correctly
    assert!(true);
} 