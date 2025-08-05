// src/routes/binary.rs
use anyhow::Result;
use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::Json,
};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

// Type alias for JSON responses
// Removed custom ResponseJson type alias
use crate::{
    AppState,
    binary::{BinaryAnalysis, ScanResult, analyze_binary, scan_binary},
};

/// Validates and sanitizes a file path to prevent path traversal attacks
/// Returns the canonicalized path if valid, or an error if the path is unsafe
/// This function is kept available for potential future web endpoints that need file path validation
#[allow(dead_code)]
pub fn validate_file_path(
    file_path: &str,
) -> Result<std::path::PathBuf, (StatusCode, Json<ErrorResponse>)> {
    // 1. Check for path traversal attempts (..) using string operations
    if file_path.contains("..") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Path traversal not allowed".to_string(),
            }),
        ));
    }

    // 2. Check for absolute paths using string operations
    if file_path.starts_with('/') || (cfg!(windows) && file_path.contains(':')) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Absolute paths not allowed".to_string(),
            }),
        ));
    }

    // 3. Create path only after validation
    let path = std::path::Path::new(file_path);

    // 4. Define allowed directory (restrict to current working directory)
    let base_dir = std::env::current_dir().map_err(|_e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                message: "Failed to get current directory".to_string(),
            }),
        )
    })?;

    // 5. Build the full path and canonicalize it
    let full_path = base_dir.join(path);
    let canonical_path = full_path.canonicalize().map_err(|_e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Invalid file path".to_string(),
            }),
        )
    })?;

    // 6. Security check: Ensure the canonicalized path is within the allowed directory
    if !canonical_path.starts_with(&base_dir) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Access denied: Path outside allowed directory".to_string(),
            }),
        ));
    }

    // 7. Check if file exists and is a regular file (not a symlink or directory)
    if !canonical_path.exists() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "file_not_found".to_string(),
                message: "File not found".to_string(),
            }),
        ));
    }

    // 8. Check if it's a regular file (not a symlink, directory, etc.)
    let metadata = std::fs::metadata(&canonical_path).map_err(|_e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "file_error".to_string(),
                message: "Cannot access file".to_string(),
            }),
        )
    })?;

    if !metadata.is_file() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Path is not a regular file".to_string(),
            }),
        ));
    }

    Ok(canonical_path)
}

#[derive(Debug, Serialize)]
pub struct BinaryUploadResponse {
    pub id: Uuid,
    pub hash: String,
    pub analysis: BinaryAnalysis,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CveScanResponse {
    pub scan_result: ScanResult,
}

pub async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "Nabla",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// POST /binary - Upload and analyze binary
pub async fn upload_and_analyze_binary(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<BinaryUploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut file_name = "unknown".to_string();
    let mut contents = vec![];
    let mut found_file = false;

    // Extract file from multipart form
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "multipart_error".to_string(),
                message: format!("Failed to parse multipart form: {}", e),
            }),
        )
    })? {
        let field_name = field.name().unwrap_or("unknown_field").to_string();
        tracing::debug!("Processing multipart field: '{}'", field_name);

        // Get filename if present
        let field_filename = field.file_name().map(|s| s.to_string());
        if let Some(name) = &field_filename {
            file_name = name.clone();
            tracing::info!("Found filename in multipart: '{}'", file_name);
        }

        // Read field contents
        let field_contents = field
            .bytes()
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "read_error".to_string(),
                        message: format!("Failed to read field '{}' contents: {}", field_name, e),
                    }),
                )
            })?
            .to_vec();

        tracing::debug!(
            "Field '{}': {} bytes, filename: {:?}",
            field_name,
            field_contents.len(),
            field_filename
        );

        // Only use content from file fields, not text fields
        if !field_contents.is_empty()
            && (
                field_name == "file"
                    || field_name == "binary"
                    || field_filename.is_some()
                    || field_contents.len() > 10
                // Assume larger content is the file
            )
        {
            contents = field_contents;
            found_file = true;
            tracing::info!(
                "Using {} bytes from field '{}' as file content",
                contents.len(),
                field_name
            );
        }
    }

    if !found_file {
        tracing::warn!("No file field found in multipart form");
    }

    if contents.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "empty_file".to_string(),
                message: "No file content provided".to_string(),
            }),
        ));
    }

    // Log the received file info
    tracing::info!("Analyzing file: '{}' ({} bytes)", file_name, contents.len());

    // Analyze the binary
    let analysis = analyze_binary(&file_name, &contents).await.map_err(|e| {
        tracing::error!("Binary analysis failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "analysis_error".to_string(),
                message: format!("Failed to analyze binary: {}", e),
            }),
        )
    })?;

    tracing::info!(
        "Analysis completed for {}: format={}, arch={}, {} strings",
        file_name,
        analysis.format,
        analysis.architecture,
        analysis.embedded_strings.len()
    );

    Ok(Json(BinaryUploadResponse {
        id: analysis.id,
        hash: analysis.hash_sha256.clone(),
        analysis,
    }))
}

use crate::binary::enterprise_scan_binary;

pub async fn check_cve(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    tracing::info!("check_cve handler called");

    let mut contents = vec![];
    let mut file_name = "uploaded.bin".to_string();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::error!("Error parsing multipart: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "multipart_error".to_string(),
                message: format!("Failed to parse multipart form: {}", e),
            }),
        )
    })? {
        tracing::info!("Found field in multipart: {:?}", field.name());

        if let Some(name) = field.file_name() {
            file_name = name.to_string();
            tracing::info!("Uploaded file: {}", file_name);
        }

        contents = field
            .bytes()
            .await
            .map_err(|e| {
                tracing::error!("Error reading file: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "read_error".to_string(),
                        message: format!("Failed to read file contents: {}", e),
                    }),
                )
            })?
            .to_vec();
    }

    if contents.is_empty() {
        tracing::warn!("No file content provided");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "empty_file".to_string(),
                message: "No file content provided".to_string(),
            }),
        ));
    }

    let analysis = analyze_binary(&file_name, &contents).await.map_err(|e| {
        tracing::error!("Binary analysis failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "analysis_error".to_string(),
                message: format!("Failed to analyze binary: {}", e),
            }),
        )
    })?;

    tracing::info!("Binary analysis complete: {:?}", analysis);

    let response_json = if state.config.enterprise_features {
        let scan_result = enterprise_scan_binary(&analysis);
        tracing::info!(
            "Enterprise vuln scan complete. {} vulnerability findings, {} security findings",
            scan_result.vulnerability_findings.len(),
            scan_result.security_findings.len()
        );
        serde_json::to_value(scan_result).unwrap_or_default()
    } else {
        let scan_result = scan_binary(&analysis);
        tracing::info!(
            "OSS vuln scan complete. {} vulnerability findings, {} security findings",
            scan_result.vulnerability_findings.len(),
            scan_result.security_findings.len()
        );
        serde_json::to_value(scan_result).unwrap_or_default()
    };

    Ok(Json(response_json))
}

// POST /binary/diff - compare two binaries
pub async fn diff_binaries(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    // Extract two files
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "multipart_error".to_string(),
                message: format!("Failed parsing multipart: {}", e),
            }),
        )
    })? {
        let name = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "file".to_string());
        let bytes = field
            .bytes()
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "read_error".to_string(),
                        message: format!("Failed to read file: {}", e),
                    }),
                )
            })?
            .to_vec();
        files.push((name, bytes));
    }

    if files.len() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Exactly two files must be provided".to_string(),
            }),
        ));
    }

    // Analyze each binary to get symbol information
    let analysis1 = analyze_binary(&files[0].0, &files[0].1)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "analysis_error".to_string(),
                    message: format!("Failed to analyze first binary: {}", e),
                }),
            )
        })?;

    let analysis2 = analyze_binary(&files[1].0, &files[1].1)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "analysis_error".to_string(),
                    message: format!("Failed to analyze second binary: {}", e),
                }),
            )
        })?;

    use sha2::Digest;
    use std::collections::HashSet;

    let mut meta = serde_json::Map::new();
    for (idx, (name, data)) in files.iter().enumerate() {
        meta.insert(format!("file{}_name", idx + 1), serde_json::json!(name));
        meta.insert(
            format!("file{}_size", idx + 1),
            serde_json::json!(data.len()),
        );
        meta.insert(
            format!("file{}_sha256", idx + 1),
            serde_json::json!(format!("{:x}", sha2::Sha256::digest(data))),
        );
    }
    meta.insert(
        "size_diff_bytes".to_string(),
        serde_json::json!((files[0].1.len() as i64) - (files[1].1.len() as i64)),
    );

    // Symbol-level diffs
    let imports1: HashSet<String> = analysis1.imports.iter().cloned().collect();
    let imports2: HashSet<String> = analysis2.imports.iter().cloned().collect();
    let exports1: HashSet<String> = analysis1.exports.iter().cloned().collect();
    let exports2: HashSet<String> = analysis2.exports.iter().cloned().collect();
    let symbols1: HashSet<String> = analysis1.detected_symbols.iter().cloned().collect();
    let symbols2: HashSet<String> = analysis2.detected_symbols.iter().cloned().collect();

    let imports_added: Vec<String> = imports2.difference(&imports1).cloned().collect();
    let imports_removed: Vec<String> = imports1.difference(&imports2).cloned().collect();
    let exports_added: Vec<String> = exports2.difference(&exports1).cloned().collect();
    let exports_removed: Vec<String> = exports1.difference(&exports2).cloned().collect();
    let symbols_added: Vec<String> = symbols2.difference(&symbols1).cloned().collect();
    let symbols_removed: Vec<String> = symbols1.difference(&symbols2).cloned().collect();

    meta.insert(
        "imports_added".to_string(),
        serde_json::json!(imports_added),
    );
    meta.insert(
        "imports_removed".to_string(),
        serde_json::json!(imports_removed),
    );
    meta.insert(
        "exports_added".to_string(),
        serde_json::json!(exports_added),
    );
    meta.insert(
        "exports_removed".to_string(),
        serde_json::json!(exports_removed),
    );
    meta.insert(
        "symbols_added".to_string(),
        serde_json::json!(symbols_added),
    );
    meta.insert(
        "symbols_removed".to_string(),
        serde_json::json!(symbols_removed),
    );

    Ok(Json(meta.into()))
}
