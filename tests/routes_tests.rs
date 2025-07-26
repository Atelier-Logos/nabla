// tests/routes_tests.rs

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use nabla::{AppState, config};
use nabla::routes::binary::{
    health_check, upload_and_analyze_binary, check_cve, diff_binaries, chat_with_binary,
    BinaryUploadResponse, ErrorResponse, CveScanResponse, ChatRequest, ChatResponse
};
use std::io::Write;
use std::sync::Arc;
use reqwest::Client;
use tokio;
use tower::ServiceExt;

#[tokio::test]
async fn test_health_check() {
    let response = health_check().await;
    let body = response.0;
    
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "Nabla");
    assert!(body["version"].is_string());
}

#[tokio::test]
async fn test_upload_and_analyze_binary_success() {
    // Prepare test binary content
    let test_binary = b"hello world";
    
    // Build multipart form
    let boundary = "---------------------------testboundary";
    let file_name = "test.bin";
    let mut data = Vec::new();
    write!(
        data,
        "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        boundary, file_name
    ).unwrap();
    data.extend_from_slice(test_binary);
    write!(data, "\r\n--{}--\r\n", boundary).unwrap();

    // Build request
    let req = Request::builder()
        .method("POST")
        .uri("/binary/analyze")
        .header("content-type", format!("multipart/form-data; boundary={}", boundary))
        .body(Body::from(data))
        .unwrap();

    // Create app state
    let config = config::Config::from_env().unwrap();
    let state = AppState {
        config,
        client: Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0; 32]),
    };

    // Build router
    let app = Router::new()
        .route("/binary/analyze", axum::routing::post(upload_and_analyze_binary))
        .with_state(state);

    // Call the route handler
    let response = app.oneshot(req).await.unwrap();
    
    // Assert response status
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_check_cve_success() {
    // Prepare test binary content
    let test_binary = b"hello world";
    
    // Build multipart form
    let boundary = "---------------------------testboundary";
    let file_name = "test.bin";
    let mut data = Vec::new();
    write!(
        data,
        "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        boundary, file_name
    ).unwrap();
    data.extend_from_slice(test_binary);
    write!(data, "\r\n--{}--\r\n", boundary).unwrap();

    // Build request
    let req = Request::builder()
        .method("POST")
        .uri("/binary/check-cves")
        .header("content-type", format!("multipart/form-data; boundary={}", boundary))
        .body(Body::from(data))
        .unwrap();

    // Create app state
    let config = config::Config::from_env().unwrap();
    let state = AppState {
        config,
        client: Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0; 32]),
    };

    // Build router
    let app = Router::new()
        .route("/binary/check-cves", axum::routing::post(check_cve))
        .with_state(state);

    // Call the route handler
    let response = app.oneshot(req).await.unwrap();
    
    // Assert response status
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_diff_binaries_success() {
    // Prepare test binary content
    let test_binary1 = b"hello world";
    let test_binary2 = b"hello world modified";
    
    // Build multipart form with two files
    let boundary = "---------------------------testboundary";
    let mut data = Vec::new();
    
    // First file
    write!(
        data,
        "--{}\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"test1.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        boundary
    ).unwrap();
    data.extend_from_slice(test_binary1);
    write!(data, "\r\n").unwrap();
    
    // Second file
    write!(
        data,
        "--{}\r\nContent-Disposition: form-data; name=\"file2\"; filename=\"test2.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        boundary
    ).unwrap();
    data.extend_from_slice(test_binary2);
    write!(data, "\r\n--{}--\r\n", boundary).unwrap();

    // Build request
    let req = Request::builder()
        .method("POST")
        .uri("/binary/diff")
        .header("content-type", format!("multipart/form-data; boundary={}", boundary))
        .body(Body::from(data))
        .unwrap();

    // Create app state
    let config = config::Config::from_env().unwrap();
    let state = AppState {
        config,
        client: Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0; 32]),
    };

    // Build router
    let app = Router::new()
        .route("/binary/diff", axum::routing::post(diff_binaries))
        .with_state(state);

    // Call the route handler
    let response = app.oneshot(req).await.unwrap();
    
    // Assert response status
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_chat_with_binary_success() {
    // Build request
    let req = Request::builder()
        .method("POST")
        .uri("/binary/chat")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"file_path":"utility_bins/vulnerable_elf","question":"Generate a CycloneDX SBOM for this binary","model_path":null,"hf_repo":null,"provider":"http","inference_url":"http://localhost:11434","provider_token":null,"options":{"max_tokens":100,"temperature":0.1,"top_p":0.9,"stop_sequences":[],"model_path":null,"hf_repo":null,"model":null}}"#))
        .unwrap();

    // Create app state
    let config = config::Config::from_env().unwrap();
    let state = AppState {
        config,
        client: Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0; 32]),
    };

    // Build router
    let app = Router::new()
        .route("/binary/chat", axum::routing::post(chat_with_binary))
        .with_state(state);

    // Call the route handler
    let response = app.oneshot(req).await.unwrap();
    
    // Note: This will likely fail due to no inference server running,
    // but we can test the request structure
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn test_response_structs() {
    // Test BinaryUploadResponse
    let upload_response = BinaryUploadResponse {
        id: uuid::Uuid::nil(),
        hash: "sha256:test".to_string(),
        analysis: nabla::binary::BinaryAnalysis {
            id: uuid::Uuid::nil(),
            file_name: "test.bin".to_string(),
            format: "application/x-elf".to_string(),
            architecture: "x86_64".to_string(),
            languages: vec![],
            detected_symbols: vec![],
            embedded_strings: vec![],
            suspected_secrets: vec![],
            imports: vec![],
            exports: vec![],
            hash_sha256: "test_hash".to_string(),
            hash_blake3: None,
            size_bytes: 100,
            linked_libraries: vec![],
            static_linked: false,
            version_info: None,
            license_info: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            sbom: None,
        },
    };
    
    assert_eq!(upload_response.hash, "sha256:test");
    assert_eq!(upload_response.analysis.file_name, "test.bin");

    // Test ErrorResponse
    let error_response = ErrorResponse {
        error: "test_error".to_string(),
        message: "Test error message".to_string(),
    };
    
    assert_eq!(error_response.error, "test_error");
    assert_eq!(error_response.message, "Test error message");

    // Test CveScanResponse
    let cve_response = CveScanResponse {
        matches: vec![],
    };
    
    assert!(cve_response.matches.is_empty());

    // Test ChatResponse
    let chat_response = ChatResponse {
        answer: "Test answer".to_string(),
        model_used: "test-model".to_string(),
        tokens_used: 10,
    };
    
    assert_eq!(chat_response.answer, "Test answer");
    assert_eq!(chat_response.model_used, "test-model");
    assert_eq!(chat_response.tokens_used, 10);
}

#[test]
fn test_chat_request_deserialization() {
    let json = r#"{
        "file_path": "test.bin",
        "question": "What is this binary?",
        "model_path": null,
        "hf_repo": null,
        "provider": "http",
        "inference_url": "http://localhost:11434",
        "provider_token": null,
        "options": {
            "max_tokens": 100,
            "temperature": 0.1,
            "top_p": 0.9,
            "stop_sequences": [],
            "model_path": null,
            "hf_repo": null,
            "model": null
        }
    }"#;
    
    let request: ChatRequest = serde_json::from_str(json).unwrap();
    
    assert_eq!(request.file_path, "test.bin");
    assert_eq!(request.question, "What is this binary?");
    assert_eq!(request.provider, "http");
    assert_eq!(request.inference_url, Some("http://localhost:11434".to_string()));
    assert!(request.provider_token.is_none());
    assert!(request.options.is_some());
} 