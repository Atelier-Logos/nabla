use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use nabla::enterprise::cloud::{MarketplaceState, marketplace_routes};

async fn create_test_app() -> Router {
    // Create a test database connection
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/nabla_test".to_string());

    let db = PgPool::connect(&database_url).await.unwrap();

    // Create marketplace state
    let marketplace_state = MarketplaceState {
        db,
        jwt_secret: "test-jwt-secret".to_string(),
        aws_entitlement_url: "https://entitlement.marketplace.us-east-1.amazonaws.com".to_string(),
        aws_access_key: "test-access-key".to_string(),
        aws_secret_key: "test-secret-key".to_string(),
        aws_region: "us-east-1".to_string(),
    };

    marketplace_routes().with_state(marketplace_state)
}

#[tokio::test]
async fn test_marketplace_register_page() {
    let app = create_test_app().await;

    // Test GET /marketplace/register with token
    let request = Request::builder()
        .method("GET")
        .uri("/marketplace/register?x_amzn_marketplace_token=test-token")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return HTML page
    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    // Should contain onboarding form
    assert!(body_str.contains("Welcome to Nabla"));
    assert!(body_str.contains("onboardingForm"));
}

#[tokio::test]
async fn test_marketplace_register_json() {
    let app = create_test_app().await;

    // Test POST /marketplace/register with JSON
    let request_body = json!({
        "x_amzn_marketplace_token": "test-token"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/marketplace/register")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return JSON response
    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    // Should contain JSON response
    assert!(body_str.contains("success"));
}

#[tokio::test]
async fn test_marketplace_onboard() {
    let app = create_test_app().await;

    // Test POST /marketplace/onboard
    let request_body = json!({
        "name": "Test User",
        "email": "test@example.com",
        "company": "Test Corp"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/marketplace/onboard")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return success response
    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    // Should contain success message
    assert!(body_str.contains("success"));
}

#[tokio::test]
async fn test_marketplace_routes_exist() {
    let app = create_test_app().await;

    // Test that marketplace routes are accessible
    let routes = [
        ("GET", "/marketplace/register"),
        ("POST", "/marketplace/register"),
        ("POST", "/marketplace/onboard"),
    ];

    for (method, path) in routes {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        // Should not return 404 (route exists)
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
}
