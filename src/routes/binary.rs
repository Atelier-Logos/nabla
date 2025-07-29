// src/routes/binary.rs
use axum::{
    extract::{Multipart, State},
    response::Json,
    http::StatusCode,
};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use serde_json::{json, Value};
use anyhow::{Result};

// Add this line to import the inference module
use crate::providers::{HTTPProvider, InferenceProvider, GenerationOptions, GenerationResponse};

// Type alias for JSON responses
// Removed custom ResponseJson type alias
use crate::{AppState, binary::{
    analyze_binary, BinaryAnalysis, 
    scan_binary_vulnerabilities, VulnerabilityMatch, 
}};

/// Validates and sanitizes a file path to prevent path traversal attacks
/// Returns the canonicalized path if valid, or an error if the path is unsafe
fn validate_file_path(file_path: &str) -> Result<std::path::PathBuf, (StatusCode, Json<ErrorResponse>)> {
    let path = std::path::Path::new(file_path);
    
    // 1. Check for path traversal attempts (..)
    if path.components().any(|c| c == std::path::Component::ParentDir) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Path traversal not allowed".to_string(),
            }),
        ));
    }
    
    // 2. Check for absolute paths
    if path.is_absolute() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Absolute paths not allowed".to_string(),
            }),
        ));
    }
    
    // 3. Define allowed directory (restrict to current working directory)
    let base_dir = std::env::current_dir().map_err(|_e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                message: "Failed to get current directory".to_string(),
            }),
        )
    })?;
    
    // 4. Build the full path and canonicalize it
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
    
    // 5. Security check: Ensure the canonicalized path is within the allowed directory
    if !canonical_path.starts_with(&base_dir) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_input".to_string(),
                message: "Access denied: Path outside allowed directory".to_string(),
            }),
        ));
    }
    
    // 6. Check if file exists and is a regular file (not a symlink or directory)
    if !canonical_path.exists() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "file_not_found".to_string(),
                message: "File not found".to_string(),
            }),
        ));
    }
    
    // 7. Check if it's a regular file (not a symlink, directory, etc.)
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
    pub matches: Vec<VulnerabilityMatch>,
}

#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub file_path: String,              // Path to the file instead of raw content
    pub question: String,
    pub model_path: Option<String>,     // For local GGUF files
    pub hf_repo: Option<String>,        // For remote HF repos
    pub provider: String,               // "http" for HTTP provider
    pub inference_url: Option<String>,  // URL for the inference server
    pub provider_token: Option<String>, // Token for third-party authentication
    pub options: Option<GenerationOptions>,
}

#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub answer: String,
    pub model_used: String,
    pub tokens_used: usize,
}

pub async fn health_check(
    State(mut state): State<AppState>,
) -> Json<serde_json::Value> {
    let fips_status = if state.config.fips_mode {
        state.crypto_provider.validate_fips_compliance().is_ok()
    } else {
        false
    };

    let fips_details = if state.config.fips_mode {
        json!({
            "fips_mode": true,
            "fips_compliant": fips_status,
            "fips_validation": state.config.fips_validation,
            "approved_algorithms": [
                "SHA-256",
                "SHA-512", 
                "HMAC-SHA256",
                "AES-256-GCM",
                "TLS13_AES_256_GCM_SHA384"
            ],
            "hash_algorithm": "SHA-512",
            "random_generator": "FIPS-compliant OS RNG"
        })
    } else {
        json!({
            "fips_mode": false,
            "fips_compliant": false,
            "fips_validation": false,
            "hash_algorithm": "Blake3",
            "random_generator": "Standard RNG"
        })
    };

    Json(json!({
        "status": "healthy",
        "service": "Nabla",
        "version": env!("CARGO_PKG_VERSION"),
        "fips": fips_details
    }))
}

// POST /binary - Upload and analyze binary
pub async fn upload_and_analyze_binary(
    State(state): State<AppState>,
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
    let analysis = analyze_binary(&file_name, &contents, &state.crypto_provider).await.map_err(|e| {
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

pub async fn check_cve(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<CveScanResponse>, (StatusCode, Json<ErrorResponse>)> {
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

        contents = field.bytes().await.map_err(|e| {
            tracing::error!("Error reading file: {}", e);
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
        tracing::warn!("No file content provided");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "empty_file".to_string(),
                message: "No file content provided".to_string(),
            }),
        ));
    }

    let analysis = analyze_binary(&file_name, &contents, &state.crypto_provider).await.map_err(|e| {
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

    let matches = scan_binary_vulnerabilities(&analysis);
    tracing::info!("Vuln scan complete. {} match(es)", matches.len());

    Ok(Json(CveScanResponse { matches }))
}


// POST /binary/diff - compare two binaries
pub async fn diff_binaries(
    State(state): State<AppState>,
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
    let analysis1 = analyze_binary(&files[0].0, &files[0].1, &state.crypto_provider).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "analysis_error".to_string(),
                message: format!("Failed to analyze first binary: {}", e),
            }),
        )
    })?;

    let analysis2 = analyze_binary(&files[1].0, &files[1].1, &state.crypto_provider).await.map_err(|e| {
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

#[axum::debug_handler]
pub async fn chat_with_binary(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Json<ChatResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate and sanitize the file path using the helper function
    let canonical_path = validate_file_path(&request.file_path)?;
    
    // Read the file using the validated canonicalized path
    let file_content = tokio::fs::read(&canonical_path).await.map_err(|_e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "file_read_error".to_string(),
                message: "Failed to read file".to_string(),
            }),
        )
    })?;
    
    // Extract filename safely from the validated canonical path
    let file_name = canonical_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    
    let analysis = analyze_binary(&file_name, &file_content, &state.crypto_provider).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "analysis_error".to_string(),
                message: format!("Failed to analyze binary: {}", e),
            }),
        )
    })?;
    
    // Store model info before moving values
    let model_used = request.hf_repo.as_ref()
        .or(request.model_path.as_ref())
        .map(|s| s.clone())
        .unwrap_or_else(|| "unknown".to_string());
    
    // Handle inference with HTTP provider
    let response = match request.provider.as_str() {
        "http" => {
            let inference_url = request.inference_url
                .unwrap_or_else(|| "http://localhost:11434".to_string());
            
            let provider = HTTPProvider::new(inference_url, None, request.provider_token);
            
            let mut options = request.options.unwrap_or_default();
            options.model_path = request.model_path;
            options.hf_repo = request.hf_repo;
            // Note: options.model is already set from the request.options if provided
            
            chat_with_provider(&analysis, &request.question, &provider, &options).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "inference_error".to_string(),
                        message: format!("Failed to chat with binary: {}", e),
                    }),
                )
            })?
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_provider".to_string(),
                    message: "Provider must be 'http'".to_string(),
                }),
            ));
        }
    };
    
    Ok(Json(ChatResponse { 
        answer: response.text,
        model_used,
        tokens_used: response.tokens_used,
    }))
}

async fn chat_with_provider(
    analysis: &BinaryAnalysis,
    user_question: &str,
    provider: &dyn InferenceProvider,
    options: &GenerationOptions,
) -> Result<GenerationResponse, anyhow::Error> {
    // Check if the question asks for JSON output
    let is_json_request = user_question.to_lowercase().contains("json") || 
                         user_question.to_lowercase().contains("sbom") ||
                         user_question.to_lowercase().contains("cyclonedx");
    
    let context = if is_json_request {
        format!(
            "Binary Analysis Context:\n\
             - File: {}\n\
             - Format: {}\n\
             - Architecture: {}\n\
             - Size: {} bytes\n\
             - Linked Libraries: {}\n\
             - Imports: {}\n\
             - Exports: {}\n\
             - Embedded Strings: {}\n\n\
             User Question: {}\n\n\
             CRITICAL: You must return ONLY raw JSON. Do NOT wrap it in quotes or escape it as a string. Return the actual JSON object directly. Do not include any explanations, markdown, or code blocks. The response should start with {{ and end with }}.",
            analysis.file_name,
            analysis.format,
            analysis.architecture,
            analysis.size_bytes,
            analysis.linked_libraries.join(", "),
            analysis.imports.join(", "),
            analysis.exports.join(", "),
            analysis.embedded_strings.join(", "),
            user_question
        )
    } else {
        format!(
        "Binary Analysis Context:\n\
         - File: {}\n\
         - Format: {}\n\
         - Architecture: {}\n\
         - Size: {} bytes\n\
         - Linked Libraries: {}\n\
         - Imports: {}\n\
         - Exports: {}\n\
         - Embedded Strings: {}\n\n\
         User Question: {}\n\n\
         Please provide a helpful answer about this binary based on the analysis data.",
        analysis.file_name,
        analysis.format,
        analysis.architecture,
        analysis.size_bytes,
        analysis.linked_libraries.join(", "),
        analysis.imports.join(", "),
        analysis.exports.join(", "),
        analysis.embedded_strings.join(", "),
        user_question
        )
    };
    
    let mut response = provider.generate(&context, options).await
        .map_err(|e| anyhow::anyhow!("Inference failed: {}", e))?;
    
    // Post-process JSON responses to handle cases where the model returns JSON as a string
    if is_json_request {
        let text = response.text.trim();
        // If the response looks like a JSON string (starts and ends with quotes), try to parse it
        if text.starts_with('"') && text.ends_with('"') {
            if let Ok(parsed_json) = serde_json::from_str::<serde_json::Value>(text) {
                response.text = serde_json::to_string(&parsed_json)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize JSON: {}", e))?;
            }
        }
    }
    
    Ok(response)
}