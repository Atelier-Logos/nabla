#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use nabla::{AppState, routes, config};
    use nabla::binary::attest_binary;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use tower::ServiceExt; // for `.oneshot()`
    use serde_json::Value;
    use std::io::Write;
    use tokio;
    use std::sync::Arc;
    use reqwest::Client;

    #[tokio::test]
    async fn test_attest_binary_success() {
        // Prepare a small binary content as the test file
        let test_binary = b"hello world";

        // Build multipart form manually
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

        // Build request with proper multipart content-type header
        let req = Request::builder()
            .method("POST")
            .uri("/binary/attest")
            .header("content-type", format!("multipart/form-data; boundary={}", boundary))
            .body(Body::from(data))
            .unwrap();

        // Create dummy app state, adjust as necessary for your app
        let config = config::Config::from_env().unwrap();


        let state = AppState {
            config,
            client: Client::new(),
            base_url: "http://localhost:8080".to_string(),
            license_jwt_secret: Arc::new([0; 32]),
        };

        // Build router with only the attest route for this test
        let app = Router::new()
            .route("/binary/attest", axum::routing::post(attest_binary))
            .with_state(state);

        // Call the route handler
        let response = app.oneshot(req).await.unwrap();

        // Assert response status
        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body as JSON
        let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap(); // 1MB max
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();

        // Assert expected keys and types
        assert_eq!(json["_type"], "https://in-toto.io/Statement/v0.1");
        assert_eq!(json["predicateType"], "https://nabla.sh/attestation/v0.1");

        let subject = &json["subject"][0];
        assert!(subject["name"].is_string());
        assert!(subject["digest"]["sha256"].is_string());

        assert!(json["predicate"]["timestamp"].is_string());
        assert!(json["predicate"]["analysis"].is_object());
    }
}