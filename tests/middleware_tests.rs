// tests/middleware_tests.rs

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use nabla::{AppState, Config, middleware::validate_license_jwt};
use std::sync::Arc;
use tower::ServiceExt;

// Mock route for testing
async fn test_protected_route() -> &'static str {
    "protected"
}

#[tokio::test]
async fn test_middleware_fips_mode_enabled() {
    // Create app state with FIPS mode enabled
    let config = Config {
        fips_mode: true,
        fips_validation: true,
        port: 8080,
        // Add other required fields
        ..Default::default()
    };

    let state = AppState {
        config,
        client: reqwest::Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0u8; 32]),
        crypto_provider: nabla::enterprise::crypto::CryptoProvider::new(true, true).unwrap(),
    };

    let app = Router::new()
        .route("/test", post(test_protected_route))
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            validate_license_jwt,
        ));

    // Test without authorization header - should fail
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_middleware_fips_mode_disabled() {
    // Create app state with FIPS mode disabled
    let config = Config {
        fips_mode: false,
        fips_validation: false,
        port: 8080,
        // Add other required fields
        ..Default::default()
    };

    let state = AppState {
        config,
        client: reqwest::Client::new(),
        base_url: "http://localhost:8080".to_string(),
        license_jwt_secret: Arc::new([0u8; 32]),
        crypto_provider: nabla::enterprise::crypto::CryptoProvider::new(false, false).unwrap(),
    };

    let app = Router::new()
        .route("/test", post(test_protected_route))
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            validate_license_jwt,
        ));

    // Test without authorization header - should succeed when FIPS mode is disabled
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "protected");
}

#[test]
fn test_config_default_implementation() {
    // Test that Config has a Default implementation
    let config = Config::default();
    assert_eq!(config.port, 8080);
    assert!(!config.fips_mode);
    assert!(!config.fips_validation);
}
