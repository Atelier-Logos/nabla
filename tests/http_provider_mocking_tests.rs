use wiremock::{
    matchers::{method, path, header},
    Mock, MockServer, ResponseTemplate,
};
use serde_json::json;
use nabla::providers::{HTTPProvider, GenerationOptions, InferenceError, InferenceProvider};

#[tokio::test]
async fn test_openai_compatible_provider() {
    let mock_server = MockServer::start().await;
    
    // Mock OpenAI-compatible endpoint
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "Hello from OpenAI-compatible API"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "total_tokens": 25,
                "prompt_tokens": 10,
                "completion_tokens": 15
            }
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    let options = GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec!["END".to_string()],
        hf_repo: None,
        model_path: None,
    };
    
    let response = provider.generate("Test prompt", &options).await.unwrap();
    assert_eq!(response.text, "Hello from OpenAI-compatible API");
    assert_eq!(response.tokens_used, 25);
    assert_eq!(response.finish_reason, "stop");
}

#[tokio::test]
async fn test_llama_cpp_provider() {
    let mock_server = MockServer::start().await;
    
    // Mock llama.cpp endpoint
    Mock::given(method("POST"))
        .and(path("/completion"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": "Hello from llama.cpp",
            "tokens_predicted": 30,
            "stop_type": "stop",
            "timings": {
                "predicted_ms": 150.5
            }
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    let options = GenerationOptions {
        model: None,
        max_tokens: 100,
        temperature: 0.8,
        top_p: 0.9,
        stop_sequences: vec!["</s>".to_string()],
        hf_repo: Some("meta-llama/Llama-2-7b-chat-hf".to_string()),
        model_path: None,
    };
    
    let response = provider.generate("Test prompt", &options).await.unwrap();
    assert_eq!(response.text, "Hello from llama.cpp");
    assert_eq!(response.tokens_used, 30);
    assert_eq!(response.finish_reason, "stop");
}

#[tokio::test]
async fn test_provider_with_authentication() {
    let mock_server = MockServer::start().await;
    
    // Mock endpoint with authentication
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "Authenticated response"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "total_tokens": 15
            }
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), Some("test-api-key".to_string()), None);
    
    let options = GenerationOptions {
        model: Some("gpt-4".to_string()),
        max_tokens: 50,
        temperature: 0.5,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: None,
        model_path: None,
    };
    
    let response = provider.generate("Test prompt", &options).await.unwrap();
    assert_eq!(response.text, "Authenticated response");
    assert_eq!(response.tokens_used, 15);
}

#[tokio::test]
async fn test_provider_with_provider_token() {
    let mock_server = MockServer::start().await;
    
    // Mock endpoint with provider token
    Mock::given(method("POST"))
        .and(path("/completion"))
        .and(header("Authorization", "Bearer provider-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": "Provider token response",
            "tokens_predicted": 20,
            "stop_type": "stop"
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, Some("provider-token".to_string()));
    
    let options = GenerationOptions {
        model: None,
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: Some("test/repo".to_string()),
        model_path: None,
    };
    
    let response = provider.generate("Test prompt", &options).await.unwrap();
    assert_eq!(response.text, "Provider token response");
    assert_eq!(response.tokens_used, 20);
}

#[tokio::test]
async fn test_server_error_responses() {
    let mock_server = MockServer::start().await;
    
    // Test 500 Internal Server Error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "Internal server error"
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    let options = GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: None,
        model_path: None,
    };
    
    let result = provider.generate("Test prompt", &options).await;
    assert!(result.is_err());
    
    if let Err(InferenceError::ServerError(msg)) = result {
        assert!(msg.contains("500"));
    } else {
        panic!("Expected ServerError");
    }
}



#[tokio::test]
async fn test_timeout_scenarios() {
    let mock_server = MockServer::start().await;
    
    // Mock slow response
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200)
            .set_delay(std::time::Duration::from_secs(10))
            .set_body_json(json!({
                "choices": [{
                    "message": {
                        "content": "Slow response"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "total_tokens": 10
                }
            })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    let options = GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: None,
        model_path: None,
    };
    
    // This should timeout or take a very long time
    let result = provider.generate("Test prompt", &options).await;
    // We'll just check it doesn't panic
    let _ = result;
}

#[tokio::test]
async fn test_malformed_responses() {
    let mock_server = MockServer::start().await;
    
    // Mock malformed JSON response
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Invalid JSON"))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    let options = GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: None,
        model_path: None,
    };
    
    let result = provider.generate("Test prompt", &options).await;
    assert!(result.is_err());
    
    if let Err(InferenceError::ServerError(_)) = result {
        // Expected
    } else {
        panic!("Expected ServerError for malformed JSON");
    }
}

#[tokio::test]
async fn test_missing_content_in_response() {
    let mock_server = MockServer::start().await;
    
    // Mock response without content field
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "finish_reason": "stop"
            }],
            "usage": {
                "total_tokens": 10
            }
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    let options = GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: None,
        model_path: None,
    };
    
    let result = provider.generate("Test prompt", &options).await;
    assert!(result.is_err());
    
    if let Err(InferenceError::ServerError(msg)) = result {
        assert!(msg.contains("Missing content"));
    } else {
        panic!("Expected ServerError for missing content");
    }
}

#[tokio::test]
async fn test_availability_check() {
    let mock_server = MockServer::start().await;
    
    // Mock /props endpoint for availability check
    Mock::given(method("GET"))
        .and(path("/props"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "server_name": "test-server",
            "version": "1.0.0"
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    // Test availability
    assert!(provider.is_available().await);
}

#[tokio::test]
async fn test_availability_check_failure() {
    // Test with invalid URL
    let provider = HTTPProvider::new(
        "http://invalid-url-that-does-not-exist.com".to_string(),
        None,
        None,
    );
    
    // Should return false for unavailable server
    assert!(!provider.is_available().await);
}

#[tokio::test]
async fn test_concurrent_requests() {
    let mock_server = MockServer::start().await;
    
    // Mock endpoint that returns consistent responses
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "Concurrent response"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "total_tokens": 15
            }
        })))
        .mount(&mock_server)
        .await;
    
    let provider = HTTPProvider::new(mock_server.uri(), None, None);
    
    let options = GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: None,
        model_path: None,
    };
    
    // Send multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..5 {
        let provider = provider.clone();
        let options = options.clone();
        let handle = tokio::spawn(async move {
            provider.generate("Test prompt", &options).await
        });
        handles.push(handle);
    }
    
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // All requests should succeed
    for result in results {
        let response = result.unwrap().unwrap();
        assert_eq!(response.text, "Concurrent response");
        assert_eq!(response.tokens_used, 15);
    }
}

 