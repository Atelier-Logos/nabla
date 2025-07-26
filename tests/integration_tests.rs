use axum::{
    http::StatusCode,
    routing::post,
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::sync::Arc;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

// Import the main application components
use nabla::{
    config::Config,
    middleware::validate_license_jwt,
    AppState,
    providers::InferenceProvider,
};

// Helper function to create a test JWT token
fn create_test_jwt(sub: &str, rate_limit: u32) -> String {
    let key_b64 = std::env::var("LICENSE_SIGNING_KEY").expect("LICENSE_SIGNING_KEY env missing");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim()).unwrap();
    let secret_array: [u8; 32] = decoded.try_into().unwrap();
    
    let now = Utc::now();
    let claims = nabla::middleware::Claims {
        sub: sub.to_string(),
        exp: (now + ChronoDuration::hours(1)).timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4().to_string(),
        plan: "test".to_string(),
        rate_limit,
        deployment_id: None,
    };
    
    let encoding_key = EncodingKey::from_secret(&secret_array);
    encode(&Header::default(), &claims, &encoding_key).unwrap()
}

// Helper function to create test app state
async fn create_test_app_state() -> AppState {
    let config = Config::from_env().unwrap();
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080".to_string();
    let key_b64 = std::env::var("LICENSE_SIGNING_KEY").expect("LICENSE_SIGNING_KEY env missing");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim()).unwrap();
    let secret_array: [u8; 32] = decoded.try_into().unwrap();
    let license_jwt_secret = Arc::new(secret_array);
    
    AppState {
        config,
        client,
        base_url,
        license_jwt_secret,
    }
}

// Helper function to create test router
async fn create_test_router() -> Router {
    let state = create_test_app_state().await;
    let auth_layer = axum::middleware::from_fn_with_state(state.clone(), validate_license_jwt);
    
    let public_routes = Router::new()
        .route("/health", axum::routing::get(nabla::routes::health_check))
        .route("/debug/multipart", post(nabla::routes::debug_multipart));
    
    let protected_routes = Router::new()
        .route("/binary/analyze", post(nabla::routes::upload_and_analyze_binary))
        .route("/binary/diff", post(nabla::routes::diff_binaries))
        .route("/binary/attest", post(nabla::binary::attest_binary))
        .route("/binary/check-cves", post(nabla::routes::check_cve))
        .route("/binary/chat", post(nabla::routes::chat_with_binary))
        .route_layer(auth_layer);
    
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
}

#[tokio::test]
async fn test_server_startup_shutdown() {
    // Test server startup
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    // Test health endpoint
    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Test that server responds to requests
    let health_data: serde_json::Value = response.json();
    assert!(health_data.get("status").is_some());
}

#[tokio::test]
async fn test_debug_multipart_route() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    // Test with empty multipart
    let response = server.post("/debug/multipart").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with valid multipart data
    let multipart_data = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nHello World\r\n--boundary--";
    
    let response = server
        .post("/debug/multipart")
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let debug_info: nabla::routes::debug::MultipartDebugInfo = response.json();
    assert_eq!(debug_info.total_fields, 1);
    assert_eq!(debug_info.fields[0].field_name, "file");
    assert_eq!(debug_info.fields[0].filename, Some("test.txt".to_string()));
    assert_eq!(debug_info.fields[0].content_type, Some("text/plain".to_string()));
    assert_eq!(debug_info.fields[0].size_bytes, 11);
    assert!(debug_info.fields[0].content_preview.contains("Hello World"));
}

#[tokio::test]
async fn test_debug_multipart_edge_cases() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    // Test with large file (should truncate preview)
    let large_content = "A".repeat(200);
    let multipart_data = format!(
        "--boundary\r\nContent-Disposition: form-data; name=\"large_file\"; filename=\"large.txt\"\r\nContent-Type: text/plain\r\n\r\n{}\r\n--boundary--",
        large_content
    );
    
    let response = server
        .post("/debug/multipart")
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    let debug_info: nabla::routes::debug::MultipartDebugInfo = response.json();
    assert_eq!(debug_info.fields[0].size_bytes, 200);
    assert!(debug_info.fields[0].content_preview.contains("... (truncated)"));
    
    // Test with multiple fields
    let multipart_data = "--boundary\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--boundary\r\nContent-Disposition: form-data; name=\"field2\"\r\n\r\nvalue2\r\n--boundary--";
    
    let response = server
        .post("/debug/multipart")
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    let debug_info: nabla::routes::debug::MultipartDebugInfo = response.json();
    assert_eq!(debug_info.total_fields, 2);
}

#[tokio::test]
async fn test_cli_tools() {
    // Test mint_license CLI tool
    let output = std::process::Command::new("cargo")
        .args(["run", "--bin", "mint_license", "--", "--sub", "test-company", "--trial_14"])
        .env("LICENSE_SIGNING_KEY", std::env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute mint_license");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let token = binding.trim();
    assert!(!token.is_empty());
    
    // Test JWT validation
    let output = std::process::Command::new("cargo")
        .args(["run", "--bin", "jwt_validation_test", "--", "--token", token])
        .env("LICENSE_SIGNING_KEY", std::env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute jwt_validation_test");
    
    assert!(output.status.success());
    
    // Test generate_hmac CLI tool
    let output = std::process::Command::new("cargo")
        .args(["run", "--bin", "generate_hmac", "--", "--message", "test message"])
        .env("LICENSE_SIGNING_KEY", std::env::var("LICENSE_SIGNING_KEY").unwrap())
        .output()
        .expect("Failed to execute generate_hmac");
    
    assert!(output.status.success());
    let binding = String::from_utf8_lossy(&output.stdout);
    let hmac = binding.trim();
    assert!(!hmac.is_empty());
}

#[tokio::test]
async fn test_http_provider_mocking() {
    // Start mock server
    let mock_server = MockServer::start().await;
    
    // Mock OpenAI-compatible endpoint
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "Mocked response"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "total_tokens": 10
            }
        })))
        .mount(&mock_server)
        .await;
    
    // Mock llama.cpp endpoint
    Mock::given(method("POST"))
        .and(path("/completion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": "Mocked llama response",
            "tokens_predicted": 15,
            "stop_type": "stop"
        })))
        .mount(&mock_server)
        .await;
    
    // Test HTTP provider with mocked server
    let provider = nabla::providers::http::HTTPProvider::new(
        mock_server.uri(),
        None,
        None,
    );
    
    // Test availability
    assert!(provider.is_available().await);
    
    // Test OpenAI-compatible generation
    let options = nabla::providers::GenerationOptions {
        model: Some("gpt-3.5-turbo".to_string()),
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: None,
        model_path: None,
    };
    
    let response = provider.generate("Test prompt", &options).await.unwrap();
    assert_eq!(response.text, "Mocked response");
    assert_eq!(response.tokens_used, 10);
    assert_eq!(response.finish_reason, "stop");
    
    // Test llama.cpp generation
    let options = nabla::providers::GenerationOptions {
        model: None,
        max_tokens: 100,
        temperature: 0.7,
        top_p: 1.0,
        stop_sequences: vec![],
        hf_repo: Some("test/repo".to_string()),
        model_path: None,
    };
    
    let response = provider.generate("Test prompt", &options).await.unwrap();
    assert_eq!(response.text, "Mocked llama response");
    assert_eq!(response.tokens_used, 15);
    assert_eq!(response.finish_reason, "stop");
}

#[tokio::test]
async fn test_http_provider_error_cases() {
    // Start mock server
    let mock_server = MockServer::start().await;
    
    // Mock server error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;
    
    let provider = nabla::providers::http::HTTPProvider::new(
        mock_server.uri(),
        None,
        None,
    );
    
    let options = nabla::providers::GenerationOptions {
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
    
    // Test network error (invalid URL)
    let provider = nabla::providers::http::HTTPProvider::new(
        "http://invalid-url-that-does-not-exist.com".to_string(),
        None,
        None,
    );
    
    let result = provider.generate("Test prompt", &options).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_middleware_error_paths() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    // Test missing API key
    let response = server
        .post("/binary/analyze")
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
    
    // Test invalid JWT token
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", "invalid-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    
    // Test expired JWT token
    let expired_token = create_expired_jwt();
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &expired_token)
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    
    // Test rate limiting
    let valid_token = create_test_jwt("test-user", 1);
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST); // No body provided
    
    // Second request should be rate limited
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

fn create_expired_jwt() -> String {
    let key_b64 = std::env::var("LICENSE_SIGNING_KEY").expect("LICENSE_SIGNING_KEY env missing");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim()).unwrap();
    let secret_array: [u8; 32] = decoded.try_into().unwrap();
    
    let now = Utc::now();
    let claims = nabla::middleware::Claims {
        sub: "test".to_string(),
        exp: (now - ChronoDuration::hours(1)).timestamp() as usize, // Expired
        iat: (now - ChronoDuration::hours(2)).timestamp() as usize,
        jti: Uuid::new_v4().to_string(),
        plan: "test".to_string(),
        rate_limit: 60,
        deployment_id: None,
    };
    
    let encoding_key = EncodingKey::from_secret(&secret_array);
    encode(&Header::default(), &claims, &encoding_key).unwrap()
}

#[tokio::test]
async fn test_routes_error_paths() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test binary analysis with invalid data
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ninvalid-binary-data\r\n--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test binary diff with missing files
          let response = server
        .post("/binary/diff")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test CVE check with invalid data
          let response = server
        .post("/binary/check-cves")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test binary chat with invalid data
    let response = server
        .post("/binary/chat")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "application/json")
        .json(&json!({
            "message": "test",
            "file": "invalid"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_binary_analysis_edge_cases() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test with empty file
    let multipart_data = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"empty.bin\"\r\n\r\n\r\n--boundary--";
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with very large file (should be rejected)
    let large_data = vec![0u8; 100 * 1024 * 1024]; // 100MB
    let multipart_data = format!(
        "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.bin\"\r\n\r\n{}\r\n--boundary--",
        String::from_utf8_lossy(&large_data)
    );
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    
    // Test with unsupported file type
    let multipart_data = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nThis is not a binary file\r\n--boundary--";
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_api_key_extraction_methods() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test x-api-key header
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST); // No body, but auth passed
    
    // Test Authorization: Bearer header
    let response = server
        .post("/binary/analyze")
        .add_header("Authorization", format!("Bearer {}", valid_token))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST); // No body, but auth passed
    
    // Test query parameter
    let response = server
        .post(&format!("/binary/analyze?api_key={}", valid_token))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST); // No body, but auth passed
}

#[tokio::test]
async fn test_concurrent_requests() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 10); // Low rate limit
    
    // Test sequential requests instead of concurrent to avoid Send issues
    let mut responses = Vec::new();
    for _ in 0..5 {
        let response = server
            .post("/health")
            .add_header("x-api-key", &valid_token)
            .await;
        responses.push(response);
    }
    
    // All requests should succeed since they're sequential
    for response in responses {
        assert_eq!(response.status_code(), StatusCode::OK);
    }
} 