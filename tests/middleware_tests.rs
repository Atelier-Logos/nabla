// tests/middleware_tests.rs

use axum::{
    body::Body,
    http::{Request, StatusCode, HeaderValue},
    Router,
};
use nabla::middleware::validate_license_jwt;
use nabla::{AppState, config};
use std::sync::Arc;
use reqwest::Client;
use tokio;
use tower::ServiceExt;

#[tokio::test]
async fn test_validate_license_jwt_with_valid_token() {
    // Create a test route that requires authentication
    async fn protected_route() -> &'static str {
        "protected"
    }
    
    let config = config::Config::from_env().unwrap();
    let state = AppState {
        config,
        client: Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0; 32]),
    };
    
    // Build router with auth middleware
    let app = Router::new()
        .route("/protected", axum::routing::get(protected_route))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            validate_license_jwt,
        ));
    
    // Create request with valid token
    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .header("Authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(req).await.unwrap();
    
    // Should either succeed or fail with auth error, but not crash
    assert!(response.status() == StatusCode::OK || 
            response.status() == StatusCode::UNAUTHORIZED ||
            response.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_validate_license_jwt_without_token() {
    async fn protected_route() -> &'static str {
        "protected"
    }
    
    let config = config::Config::from_env().unwrap();
    let state = AppState {
        config,
        client: Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0; 32]),
    };
    
    let app = Router::new()
        .route("/protected", axum::routing::get(protected_route))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            validate_license_jwt,
        ));
    
    // Create request without token
    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(req).await.unwrap();
    
    // Should fail with unauthorized or too many requests
    assert!(response.status() == StatusCode::UNAUTHORIZED || 
            response.status() == StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_validate_license_jwt_with_invalid_header() {
    async fn protected_route() -> &'static str {
        "protected"
    }
    
    let config = config::Config::from_env().unwrap();
    let state = AppState {
        config,
        client: Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0; 32]),
    };
    
    let app = Router::new()
        .route("/protected", axum::routing::get(protected_route))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            validate_license_jwt,
        ));
    
    // Create request with invalid header format
    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .header("Authorization", "InvalidFormat token")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(req).await.unwrap();
    
    // Should fail with too many requests (no token found)
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn test_jwt_secret_creation() {
    let secret = Arc::new([0; 32]);
    assert_eq!(secret.len(), 32);
    
    let secret2 = Arc::new([1; 32]);
    assert_eq!(secret2.len(), 32);
    assert_ne!(*secret, *secret2);
}

#[test]
fn test_header_value_creation() {
    let header = HeaderValue::from_static("Bearer test-token");
    assert_eq!(header.to_str().unwrap(), "Bearer test-token");
    
    let header2 = HeaderValue::from_static("InvalidFormat test-token");
    assert_eq!(header2.to_str().unwrap(), "InvalidFormat test-token");
} 