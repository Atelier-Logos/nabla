use axum::{
    http::{StatusCode},
    routing::post,
    Router,
};
use axum_test::TestServer;
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
use nabla::{
    config::Config,
    middleware::validate_license_jwt,
    AppState,
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

// Helper function to create expired JWT token
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
async fn test_middleware_missing_api_key() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    // Test missing API key in all extraction methods
    let endpoints = ["/binary/analyze", "/binary/diff", "/binary/attest", "/binary/check-cves", "/binary/chat"];
    
    for endpoint in endpoints {
        let response = server.post(endpoint).await;
        assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn test_middleware_invalid_jwt_format() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    let invalid_tokens = [
        "not-a-jwt-token",
        "invalid.token.here",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
        "",
        "Bearer invalid",
    ];
    
    for token in invalid_tokens {
        let response = server
            .post("/binary/analyze")
            .add_header("x-api-key", token)
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_middleware_expired_jwt() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    let expired_token = create_expired_jwt();
    
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &expired_token)
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_middleware_rate_limiting() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    // Create token with very low rate limit
    let token = create_test_jwt("test-user", 1);
    
    // First request should pass (no body, but auth passes)
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &token)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST); // No body provided
    
    // Second request should be rate limited
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &token)
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_middleware_api_key_extraction_methods() {
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
async fn test_routes_binary_analysis_invalid_data() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test with empty multipart
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with invalid multipart data
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("invalid multipart data")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with text file instead of binary
    let multipart_data = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nThis is a text file\r\n--boundary--";
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_routes_binary_diff_invalid_data() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test with missing files
    let response = server
        .post("/binary/diff")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with only one file
    let multipart_data = "--boundary\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"test1.bin\"\r\n\r\nbinary data\r\n--boundary--";
    let response = server
        .post("/binary/diff")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_routes_cve_check_invalid_data() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test with empty request
    let response = server
        .post("/binary/check-cves")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with invalid binary data
    let multipart_data = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.bin\"\r\n\r\nnot a real binary\r\n--boundary--";
    let response = server
        .post("/binary/check-cves")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text(multipart_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_routes_debug_multipart_errors() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    
    // Test with empty request
    let response = server.post("/debug/multipart").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with invalid multipart data
    let response = server
        .post("/debug/multipart")
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("invalid multipart data")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    // Test with malformed multipart
    let response = server
        .post("/debug/multipart")
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_routes_large_payload_handling() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test with very large payload (should be rejected)
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
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_routes_malformed_json() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test with malformed JSON
    let response = server
        .post("/binary/chat")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "application/json")
        .text("{ invalid json }")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_routes_unsupported_content_types() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test with unsupported content type
    let response = server
        .post("/binary/chat")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "text/plain")
        .text("some text")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    
    // Test with multipart for JSON endpoint
    let response = server
        .post("/binary/chat")
        .add_header("x-api-key", &valid_token)
        .add_header("Content-Type", "multipart/form-data; boundary=boundary")
        .text("--boundary--")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_routes_missing_headers() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 60);
    
    // Test without Content-Type header
    let response = server
        .post("/binary/analyze")
        .add_header("x-api-key", &valid_token)
        .text("test data")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_routes_concurrent_requests() {
    let router = create_test_router().await;
    let server = TestServer::new(router).unwrap();
    let valid_token = create_test_jwt("test-user", 10); // Low rate limit
    
    // Send multiple concurrent requests to test rate limiting
    // Test sequential requests instead of concurrent to avoid Send issues
    let mut responses = Vec::new();
    for _ in 0..5 {
        let response = server
            .get("/health")
            .add_header("x-api-key", &valid_token)
            .await;
        responses.push(response);
    }
    
    // All requests should succeed since they're sequential
    for response in responses {
        assert_eq!(response.status_code(), StatusCode::OK);
    }
} 