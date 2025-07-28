use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::{json};
use chrono::Utc;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine as _};
use hex;
use crate::{AppState, binary::analyze_binary};

pub async fn attest_binary(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Extract binary file from multipart
    let mut file_bytes = None;
    let mut file_name = None;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            file_name = field.file_name().map(str::to_string);
            file_bytes = Some(field.bytes().await.unwrap_or_default());
        }
    }

    let file_bytes = match file_bytes {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => return (StatusCode::BAD_REQUEST, "Missing or empty binary").into_response(),
    };

    // Compute SHA256 digest for reference
    let mut hasher = Sha256::new();
    hasher.update(&file_bytes);
    let hash = hasher.finalize();
    let _encoded_hash = general_purpose::STANDARD.encode(&hash);

    // Run your internal analysis logic
    let analysis_struct = match analyze_binary(
        file_name.as_deref().unwrap_or("uploaded-binary"),
        &file_bytes,
        &state.crypto_provider
    ).await {
        Ok(data) => data,
        Err(err) => {
            tracing::error!("Analysis failed: {:?}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Analysis failed").into_response();
        }
    };
    
    // Serialize to JSON Value
    let analysis = match serde_json::to_value(&analysis_struct) {
        Ok(val) => val,
        Err(err) => {
            tracing::error!("Serialization failed: {:?}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Serialization failed").into_response();
        }
    };

    let encoded_hash = hex::encode(&hash);

    let attestation = json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{
            "name": file_name.unwrap_or_else(|| "uploaded-binary".into()),
            "digest": {
                "sha256": encoded_hash
            }
        }],
        "predicateType": "https://nabla.sh/attestation/v0.1",
        "predicate": {
            "timestamp": Utc::now().to_rfc3339(),
            "analysis": analysis
        }
    });

    (StatusCode::OK, Json(attestation)).into_response()
}
