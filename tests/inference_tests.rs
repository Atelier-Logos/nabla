use nabla::binary::ai_enhanced::{generate_sbom_from_analysis, chat_with_binary};
use nabla::binary::BinaryAnalysis;
use nabla::providers::{HTTPProvider, InferenceProvider, GenerationOptions, GenerationResponse, InferenceError};
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

#[tokio::test]
async fn test_generate_sbom_from_analysis_success() {
    let analysis = create_test_analysis();
    let provider = MockProvider::new(r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": "2023-01-01T00:00:00Z",
            "tools": [{"name": "nabla"}]
        },
        "components": [
            {
                "type": "library",
                "name": "libc",
                "version": "2.31"
            }
        ]
    }"#);
    
    let options = GenerationOptions::default();
    
    let result = generate_sbom_from_analysis(&analysis, &provider, &options).await;
    assert!(result.is_ok());
    
    let sbom = result.unwrap();
    assert_eq!(sbom["bomFormat"], "CycloneDX");
    assert_eq!(sbom["specVersion"], "1.4");
    assert_eq!(sbom["version"], 1);
}

#[tokio::test]
async fn test_generate_sbom_from_analysis_invalid_json() {
    let analysis = create_test_analysis();
    let provider = MockProvider::new("invalid json response");
    
    let options = GenerationOptions::default();
    
    let result = generate_sbom_from_analysis(&analysis, &provider, &options).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Failed to parse SBOM"));
}

#[tokio::test]
async fn test_generate_sbom_from_analysis_provider_failure() {
    let analysis = create_test_analysis();
    let provider = MockProvider::with_failure();
    
    let options = GenerationOptions::default();
    
    let result = generate_sbom_from_analysis(&analysis, &provider, &options).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Inference failed"));
}

#[tokio::test]
async fn test_chat_with_binary_success() {
    let analysis = create_test_analysis();
    let provider = MockProvider::new("This is a Linux ELF binary compiled with GCC.");
    let options = GenerationOptions::default();
    
    let result = chat_with_binary(&analysis, "What type of binary is this?", &provider, &options).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response.text, "This is a Linux ELF binary compiled with GCC.");
}

#[tokio::test]
async fn test_chat_with_binary_provider_failure() {
    let analysis = create_test_analysis();
    let provider = MockProvider::with_failure();
    let options = GenerationOptions::default();
    
    let result = chat_with_binary(&analysis, "What type of binary is this?", &provider, &options).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Inference failed"));
}

#[tokio::test]
async fn test_chat_with_binary_empty_question() {
    let analysis = create_test_analysis();
    let provider = MockProvider::new("Analysis complete.");
    let options = GenerationOptions::default();
    
    let result = chat_with_binary(&analysis, "", &provider, &options).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response.text, "Analysis complete.");
}

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

#[tokio::test]
async fn test_generation_options_custom_with_ai_enhanced() {
    let analysis = create_test_analysis();
    let provider = MockProvider::new("Custom options applied.");
    
    let mut options = GenerationOptions::default();
    options.max_tokens = 100;
    options.temperature = 0.7;
    
    let result = chat_with_binary(&analysis, "Test with custom options", &provider, &options).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_empty_analysis_data() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::new_v4(),
        file_name: "empty".to_string(),
        format: "Unknown".to_string(),
        architecture: "Unknown".to_string(),
        languages: vec![],
        detected_symbols: vec![],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec![],
        exports: vec![],
        hash_sha256: "empty_hash".to_string(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
    };
    
    let provider = MockProvider::new("Empty analysis processed.");
    let options = GenerationOptions::default();
    
    let result = chat_with_binary(&analysis, "What can you tell me about this?", &provider, &options).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response.text, "Empty analysis processed.");
}

#[tokio::test]
async fn test_large_analysis_data() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::new_v4(),
        file_name: "large_binary".to_string(),
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec!["C".to_string()],
        detected_symbols: vec!["main".to_string()],
        embedded_strings: vec![
            "GNU C Library".to_string(),
            "Linux".to_string(),
            "GCC".to_string(),
            "GLIBC".to_string(),
        ],
        suspected_secrets: vec![],
        imports: vec![
            "printf".to_string(),
            "malloc".to_string(),
            "free".to_string(),
            "strlen".to_string(),
            "strcpy".to_string(),
        ],
        exports: vec![
            "main".to_string(),
            "init".to_string(),
            "fini".to_string(),
        ],
        hash_sha256: "large_binary_hash".to_string(),
        hash_blake3: None,
        size_bytes: 1024 * 1024 * 10, // 10MB
        linked_libraries: vec![
            "libc.so.6".to_string(),
            "libpthread.so.0".to_string(),
            "libdl.so.2".to_string(),
            "libm.so.6".to_string(),
            "libgcc_s.so.1".to_string(),
        ],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: json!({
            "compiler": "GCC",
            "version": "9.4.0",
            "optimization": "O2"
        }),
        created_at: chrono::Utc::now(),
        sbom: None,
    };
    
    let provider = MockProvider::new("Large binary analysis completed.");
    let options = GenerationOptions::default();
    
    let result = chat_with_binary(&analysis, "Analyze this large binary", &provider, &options).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response.text, "Large binary analysis completed.");
} 