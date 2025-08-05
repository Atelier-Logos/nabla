// tests/middleware_tests.rs

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use nabla_cli::{AppState, Config, config::DeploymentType, middleware::validate_license_jwt};
use std::sync::Arc;
use tower::ServiceExt;

// Mock route for testing
async fn test_protected_route() -> &'static str {
    "protected"
}

#[tokio::test]
async fn test_middleware_fips_mode_enabled() {
    // Create app state for NablaSecure deployment
    let config = Config {
        deployment_type: DeploymentType::NablaSecure,
        enterprise_features: true,
        port: 8080,
        // Add other required fields
        ..Default::default()
    };

    let state = AppState {
        config: config.clone(),
        client: reqwest::Client::new(),
        base_url: "http://localhost:8080".to_string(),
        enterprise_features: config.enterprise_features,
        license_jwt_secret: Arc::new([0u8; 32]),
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
    // Create app state for OSS deployment
    let config = Config {
        deployment_type: DeploymentType::OSS,
        enterprise_features: false,
        port: 8080,
        // Add other required fields
        ..Default::default()
    };

    let state = AppState {
        config: config.clone(),
        client: reqwest::Client::new(),
        base_url: "http://localhost:8080".to_string(),
        enterprise_features: config.enterprise_features,
        license_jwt_secret: Arc::new([0u8; 32]),
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
    assert_eq!(config.deployment_type, DeploymentType::OSS);
    assert!(!config.enterprise_features);
}
