// src/routes/binary.rs
use axum::{
    extract::{Multipart, State, Path, Query},
    response::Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use crate::{AppState, binary::{
    analyze_binary, BinaryAnalysis, SecretScanner, SecretScanResult, 
    generate_sbom, SbomFormat
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

// POST /binary - Upload and analyze binary
pub async fn upload_and_analyze_binary(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<BinaryUploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut file_name = "unknown".to_string();
    let mut contents = vec![];

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
        if let Some(name) = field.file_name().map(|s| s.to_string()) {
            file_name = name;
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

    // Analyze the binary
    let analysis = analyze_binary(&file_name, &contents).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "analysis_error".to_string(),
                message: format!("Failed to analyze binary: {}", e),
            }),
        )
    })?;

    // Store in database (simplified for now, you'd want proper DB schema)
    let query = "INSERT INTO binaries (id, file_name, hash_sha256, analysis_data, contents, created_at) 
                 VALUES ($1, $2, $3, $4, $5, $6)";
    
    sqlx::query(query)
        .bind(&analysis.id)
        .bind(&analysis.file_name)
        .bind(&analysis.hash_sha256)
        .bind(serde_json::to_value(&analysis).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "serialization_error".to_string(),
                    message: format!("Failed to serialize analysis: {}", e),
                }),
            )
        })?)
        .bind(&contents)
        .bind(&analysis.created_at)
        .execute(&state.pool.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: format!("Failed to store analysis: {}", e),
                }),
            )
        })?;

    Ok(Json(BinaryUploadResponse {
        id: analysis.id,
        hash: analysis.hash_sha256.clone(),
        analysis,
    }))
}

// GET /binary/:hash - Get existing analysis by hash
pub async fn get_binary_analysis(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<BinaryAnalysis>, (StatusCode, Json<ErrorResponse>)> {
    let query = "SELECT analysis_data FROM binaries WHERE hash_sha256 = $1";
    
    let row = sqlx::query(query)
        .bind(&hash)
        .fetch_optional(&state.pool.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: format!("Database query failed: {}", e),
                }),
            )
        })?;

    match row {
        Some(row) => {
            let analysis_data: serde_json::Value = row.get("analysis_data");
            let analysis: BinaryAnalysis = serde_json::from_value(analysis_data).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "deserialization_error".to_string(),
                        message: format!("Failed to deserialize analysis: {}", e),
                    }),
                )
            })?;
            Ok(Json(analysis))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("No binary analysis found for hash: {}", hash),
            }),
        )),
    }
}

// POST /binary/scan-secrets - Scan for secrets in binary
pub async fn scan_binary_secrets(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<SecretScanResult>, (StatusCode, Json<ErrorResponse>)> {
    let mut contents = vec![];

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

    // Initialize secret scanner
    let scanner = SecretScanner::new().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scanner_init_error".to_string(),
                message: format!("Failed to initialize secret scanner: {}", e),
            }),
        )
    })?;

    // Scan for secrets
    let scan_result = scanner.scan_binary(&contents).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: format!("Failed to scan for secrets: {}", e),
            }),
        )
    })?;

    Ok(Json(scan_result))
}

// GET /binary/:hash/sbom - Get SBOM for a binary
pub async fn get_binary_sbom(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    Query(params): Query<SbomQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // First get the binary analysis
    let query = "SELECT analysis_data FROM binaries WHERE hash_sha256 = $1";
    
    let row = sqlx::query(query)
        .bind(&hash)
        .fetch_optional(&state.pool.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: format!("Database query failed: {}", e),
                }),
            )
        })?;

    let analysis_data: serde_json::Value = match row {
        Some(row) => row.get("analysis_data"),
        None => return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("No binary analysis found for hash: {}", hash),
            }),
        )),
    };

    let analysis: BinaryAnalysis = serde_json::from_value(analysis_data).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "deserialization_error".to_string(),
                message: format!("Failed to deserialize analysis: {}", e),
            }),
        )
    })?;

    // Determine SBOM format
    let format = match params.format.as_deref() {
        Some("spdx") => SbomFormat::Spdx,
        Some("cyclonedx") => SbomFormat::CycloneDx,
        Some(other) => return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_format".to_string(),
                message: format!("Invalid SBOM format: {}. Use 'spdx' or 'cyclonedx'", other),
            }),
        )),
        None => SbomFormat::Spdx, // Default to SPDX
    };

    // Generate SBOM
    let sbom = generate_sbom(&analysis, format).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "sbom_generation_error".to_string(),
                message: format!("Failed to generate SBOM: {}", e),
            }),
        )
    })?;

    Ok(Json(sbom))
}
