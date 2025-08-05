use crate::{AppState, binary::analyze_binary};
use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::Json,
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use hex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
// Removed unused imports
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

pub async fn attest_binary(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    // For now, assume attestation is available (middleware should handle this)
    // In a full implementation, you'd extract features from request extensions

    // Extract binary file from multipart
    let mut file_bytes = None;
    let mut file_name = None;
    let mut signing_key_bytes = None;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                file_name = field.file_name().map(str::to_string);
                file_bytes = Some(field.bytes().await.unwrap_or_default());
            }
            "signing_key" => {
                signing_key_bytes = Some(field.bytes().await.unwrap_or_default());
            }
            _ => {}
        }
    }

    let file_bytes = match file_bytes {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_file".to_string(),
                    message: "Missing or empty binary".to_string(),
                }),
            ));
        }
    };

    // Check if signing key is provided (required for attestation)
    if signing_key_bytes.is_none() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "signing_key_required".to_string(),
            message: "Signing key is required for binary attestation. Please provide a valid signing key.".to_string(),
        })));
    }

    // Compute SHA256 digest for reference
    let mut hasher = Sha256::new();
    hasher.update(&file_bytes);
    let hash = hasher.finalize();
    let _encoded_hash = general_purpose::STANDARD.encode(&hash);

    // Run your internal analysis logic
    let analysis_struct = match analyze_binary(
        file_name.as_deref().unwrap_or("uploaded-binary"),
        &file_bytes,
    )
    .await
    {
        Ok(data) => data,
        Err(err) => {
            tracing::error!("Analysis failed: {:?}", err);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "analysis_failed".to_string(),
                    message: "Analysis failed".to_string(),
                }),
            ));
        }
    };

    // Serialize to JSON Value
    let analysis = match serde_json::to_value(&analysis_struct) {
        Ok(val) => val,
        Err(err) => {
            tracing::error!("Serialization failed: {:?}", err);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "serialization_failed".to_string(),
                    message: "Serialization failed".to_string(),
                }),
            ));
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
        "predicateType": "https://www.usenabla.com/attestation/v0.1",
        "predicate": {
            "timestamp": Utc::now().to_rfc3339(),
            "analysis": analysis
        }
    });

    // Create signed attestation with the provided key
    let signing_key = signing_key_bytes.unwrap();
    match create_signed_attestation(&attestation, &signing_key) {
        Ok(signed_attestation) => Ok(Json(signed_attestation)),
        Err(err) => {
            tracing::error!("Signing failed: {:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "signing_failed".to_string(),
                    message: "Signing failed".to_string(),
                }),
            ))
        }
    }
}

fn create_signed_attestation(
    attestation: &serde_json::Value,
    signing_key: &[u8],
) -> anyhow::Result<serde_json::Value> {
    // Parse the signing key (PEM format)
    let key_pair = match parse_signing_key(signing_key) {
        Ok(key) => key,
        Err(_) => {
            return Err(anyhow::anyhow!("Invalid signing key format"));
        }
    };

    // Create the signature
    let attestation_bytes = serde_json::to_vec(attestation)?;
    let signature = key_pair
        .try_sign(&attestation_bytes)
        .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;
    let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Create the signed attestation
    let mut signed_attestation = attestation.clone();
    let signatures = json!([{
        "keyid": "keyid123", // In a real implementation, this would be derived from the key
        "sig": signature_b64,
        "cert": "certificate_here" // In a real implementation, this would be the actual certificate
    }]);

    if let Some(obj) = signed_attestation.as_object_mut() {
        obj.insert("signatures".to_string(), signatures);
    }

    Ok(signed_attestation)
}

fn parse_signing_key(key_bytes: &[u8]) -> anyhow::Result<ed25519_dalek::SigningKey> {
    // Parse PEM format
    let key_str = String::from_utf8_lossy(key_bytes);

    // Remove PEM headers and decode base64
    let pem_content = if key_str.contains("-----BEGIN PRIVATE KEY-----") {
        let lines: Vec<&str> = key_str.lines().collect();
        let mut key_content = String::new();
        let mut in_key = false;

        for line in lines {
            if line.contains("-----BEGIN PRIVATE KEY-----") {
                in_key = true;
                continue;
            }
            if line.contains("-----END PRIVATE KEY-----") {
                break;
            }
            if in_key {
                key_content.push_str(line);
            }
        }

        general_purpose::STANDARD.decode(key_content.as_bytes())?
    } else {
        // Assume it's already base64 encoded
        general_purpose::STANDARD.decode(key_bytes)?
    };

    // Ensure we have exactly 32 bytes for Ed25519
    if pem_content.len() != 32 {
        return Err(anyhow::anyhow!(
            "Invalid key length: expected 32 bytes, got {}",
            pem_content.len()
        ));
    }

    // Convert Vec<u8> to [u8; 32]
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&pem_content);

    // Create signing key from bytes
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
    Ok(signing_key)
}
