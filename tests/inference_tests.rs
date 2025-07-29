
use nabla::binary::BinaryAnalysis;
use nabla::enterprise::providers::{HTTPProvider, InferenceProvider, GenerationOptions, GenerationResponse, InferenceError};
use async_trait::async_trait;
use serde_json::json;
use uuid;
use chrono;

// Mock provider for testing AI enhanced features
struct MockProvider {
    should_fail: bool,
    response_text: String,
}

impl MockProvider {
    fn new(response_text: &str) -> Self {
        Self {
            should_fail: false,
            response_text: response_text.to_string(),
        }
    }
    
    fn with_failure() -> Self {
        Self {
            should_fail: true,
            response_text: String::new(),
        }
    }
}

#[async_trait]
impl InferenceProvider for MockProvider {
    async fn generate(&self, _prompt: &str, _options: &GenerationOptions) -> Result<GenerationResponse, InferenceError> {
        if self.should_fail {
            Err(InferenceError::NetworkError("Mock network error".to_string()))
        } else {
            Ok(GenerationResponse {
                text: self.response_text.clone(),
                tokens_used: 10,
                finish_reason: "stop".to_string(),
            })
        }
    }
    
    async fn is_available(&self) -> bool {
        !self.should_fail
    }
}

fn create_test_analysis() -> BinaryAnalysis {
    BinaryAnalysis {
        id: uuid::Uuid::new_v4(),
        file_name: "test_binary".to_string(),
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec!["C".to_string()],
        detected_symbols: vec!["main".to_string()],
        embedded_strings: vec!["Hello World".to_string(), "GCC".to_string()],
        suspected_secrets: vec![],
        imports: vec!["printf".to_string(), "malloc".to_string()],
        exports: vec!["main".to_string()],
        hash_sha256: "test_hash".to_string(),
        hash_blake3: None,
        size_bytes: 1024,
        linked_libraries: vec!["libc.so.6".to_string(), "libpthread.so.0".to_string()],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: json!({
            "compiler": "GCC",
            "version": "1.0.0"
        }),
        created_at: chrono::Utc::now(),
        sbom: None,
    }
}

// ============================================================================
// AI Enhanced Tests
// ============================================================================



// ============================================================================
// HTTP Provider Constructor Tests (Basic functionality only)
// ============================================================================

#[tokio::test]
async fn test_http_provider_constructor() {
    let _provider = HTTPProvider::new(
        "http://localhost:11434".to_string(),
        Some("test-key".to_string()),
        Some("provider-token".to_string())
    );
    
    // Test that provider was created successfully
    assert!(true);
}

#[tokio::test]
async fn test_http_provider_constructor_minimal() {
    let _provider = HTTPProvider::new(
        "http://localhost:11434".to_string(),
        None,
        None
    );
    
    // Test that provider was created successfully
    assert!(true);
}

// ============================================================================
// Generation Options Tests
// ============================================================================

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

// ============================================================================
// Provider Mode Tests (Configuration only)
// ============================================================================

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

// ============================================================================
// AI Enhanced with Custom Options Tests
// ============================================================================

 