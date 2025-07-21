// src/routes/binary.rs
use axum::{
    extract::{Multipart, State, Path, Query},
    response::Json,
    http::StatusCode,
    Extension,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use serde_json::json;

// Type alias for JSON responses
// Removed custom ResponseJson type alias
use crate::{AppState, binary::{
    analyze_binary, BinaryAnalysis, 
    generate_sbom, scan_binary_vulnerabilities, VulnerabilityMatch
}};

#[derive(Debug, Deserialize)]
pub struct SbomQuery {
    pub format: Option<String>, // "spdx" or "cyclonedx"
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
    pub matches: Vec<VulnerabilityMatch>,
}

pub async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "Nabla",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

// POST /binary - Upload and analyze binary
pub async fn upload_and_analyze_binary(
    State(state): State<AppState>,
    Extension(api_key): Extension<crate::middleware::ApiKeyRecord>,
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
        let field_contents = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "read_error".to_string(),
                    message: format!("Failed to read field '{}' contents: {}", field_name, e),
                }),
            )
        })?.to_vec();
        
        tracing::debug!("Field '{}': {} bytes, filename: {:?}", 
                       field_name, field_contents.len(), field_filename);
        
        // Only use content from file fields, not text fields
        if !field_contents.is_empty() && (
            field_name == "file" || 
            field_name == "binary" || 
            field_filename.is_some() ||
            field_contents.len() > 10 // Assume larger content is the file
        ) {
            contents = field_contents;
            found_file = true;
            tracing::info!("Using {} bytes from field '{}' as file content", contents.len(), field_name);
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
    
    tracing::info!("Analysis completed for {}: format={}, arch={}, {} strings", 
                   file_name, analysis.format, analysis.architecture, analysis.embedded_strings.len());



    Ok(Json(BinaryUploadResponse {
        id: analysis.id,
        hash: analysis.hash_sha256.clone(),
        analysis,
    }))
}

// POST /binary/check-cves - Scan for CVEs
pub async fn check_cve(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<CveScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut contents = vec![];
    let mut file_name = "uploaded.bin".to_string();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "multipart_error".to_string(),
                message: format!("Failed to parse multipart form: {}", e),
            }),
        )
    })? {
        if let Some(name) = field.file_name() {
            file_name = name.to_string();
        }
        contents = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "read_error".to_string(),
                    message: format!("Failed to read file contents: {}", e),
                }),
            )
        })?.to_vec();
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

    // Perform a lightweight binary analysis to gather imports/libraries
    let analysis = analyze_binary(&file_name, &contents).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "analysis_error".to_string(),
                message: format!("Failed to analyze binary: {}", e),
            }),
        )
    })?;

    let matches = scan_binary_vulnerabilities(&analysis);

    Ok(Json(CveScanResponse { matches }))
}

// POST /binary/diff - compare two binaries
pub async fn diff_binaries(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
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
        let name = field.file_name().map(|s| s.to_string()).unwrap_or_else(|| "file".to_string());
        let bytes = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "read_error".to_string(),
                    message: format!("Failed to read file: {}", e),
                }),
            )
        })?.to_vec();
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
    let analysis1 = analyze_binary(&files[0].0, &files[0].1).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "analysis_error".to_string(),
                message: format!("Failed to analyze first binary: {}", e),
            }),
        )
    })?;

    let analysis2 = analyze_binary(&files[1].0, &files[1].1).await.map_err(|e| {
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
        meta.insert(format!("file{}_name", idx+1), serde_json::json!(name));
        meta.insert(format!("file{}_size", idx+1), serde_json::json!(data.len()));
        meta.insert(format!("file{}_sha256", idx+1), serde_json::json!(format!("{:x}", sha2::Sha256::digest(data))));
    }
    meta.insert("size_diff_bytes".to_string(), serde_json::json!((files[0].1.len() as i64) - (files[1].1.len() as i64)));

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

    meta.insert("imports_added".to_string(), serde_json::json!(imports_added));
    meta.insert("imports_removed".to_string(), serde_json::json!(imports_removed));
    meta.insert("exports_added".to_string(), serde_json::json!(exports_added));
    meta.insert("exports_removed".to_string(), serde_json::json!(exports_removed));
    meta.insert("symbols_added".to_string(), serde_json::json!(symbols_added));
    meta.insert("symbols_removed".to_string(), serde_json::json!(symbols_removed));

    Ok(Json(meta.into()))
}
