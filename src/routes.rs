use axum::{
    extract::{State, Json},
    extract::Path,
    http::StatusCode,
    response::Json as ResponseJson,
    http::{header, Method},
    routing::post,
    routing::get,
    Router,
    Extension,
};
use serde_json::json;
use uuid::Uuid;
use crate::middleware::ApiKeyRecord;

use crate::{
    AppState,
    models::{AnalyzeRequest, AnalyzeResponse},
    analysis::PackageAnalyzer,
};

pub async fn health_check() -> ResponseJson<serde_json::Value> {
    ResponseJson(json!({
        "status": "healthy",
        "service": "ferropipe-audit",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[allow(clippy::too_many_arguments)]
pub async fn analyze_package(
    State(app_state): State<AppState>,
    Extension(api_key): Extension<ApiKeyRecord>,
    Json(mut request): Json<AnalyzeRequest>,
) -> Result<ResponseJson<AnalyzeResponse>, (StatusCode, ResponseJson<AnalyzeResponse>)> {
    tracing::info!("Received analysis request for {}:{}", request.name, request.version);

    let key_id = api_key.id;

    // ---------------- Determine extraction depth ----------------
    let mut depth_normalized = request.extraction_depth.trim().to_lowercase();

    // If client didn't supply or supplied an unknown value, fall back to tier mapping
    let allowed = ["basic", "full", "deep"];
    if !allowed.contains(&depth_normalized.as_str()) {
        depth_normalized = match api_key.tier.as_str() {
            "professional" => "full".to_string(),
            "enterprise" => "deep".to_string(),
            _ => "basic".to_string(),
        };
    }

    request.extraction_depth = depth_normalized.clone();

    tracing::info!("Extraction depth for analysis: {}", request.extraction_depth);

    // ---------------- Determine cache expiry -------------------
    if request.cache_expires_at.is_none() {
        use chrono::{Duration, Utc};
        let duration = match api_key.tier.as_str() {
            "professional" => Duration::days(14),
            "enterprise" => Duration::days(7),
            _ => Duration::days(30),
        };
        request.cache_expires_at = Some(Utc::now() + duration);
    }

    // Validate input parameters
    if request.name.is_empty() || request.version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(AnalyzeResponse {
                success: false,
                package_id: None,
                message: "Package name and version are required".to_string(),
                full_analysis: None,
            })
        ));
    }

    // Create analyzer and download package
    let analyzer = match PackageAnalyzer::new(&request.name, &request.version).await {
        Ok(analyzer) => analyzer,
        Err(e) => {
            tracing::error!("Failed to create analyzer for {}:{}: {}", 
                request.name, request.version, e);
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(AnalyzeResponse {
                    success: false,
                    package_id: None,
                    message: format!("Failed to download package: {}", e),
                    full_analysis: None,
                })
            ));
        }
    };

    // Run the analysis
    let analysis = match analyzer.analyze(&request, key_id).await {
        Ok(analysis) => analysis,
        Err(e) => {
            tracing::error!("Analysis failed for {}:{}: {}", 
                request.name, request.version, e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(AnalyzeResponse {
                    success: false,
                    package_id: None,
                    message: format!("Analysis failed: {}", e),
                    full_analysis: None,
                })
            ));
        }
    };

    // Insert results into database
    let package_id = match app_state.pool.insert_package_analysis(&analysis).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Failed to insert analysis results: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(AnalyzeResponse {
                    success: false,
                    package_id: None,
                    message: "Failed to save analysis results".to_string(),
                    full_analysis: None,
                })
            ));
        }
    };

    tracing::info!("Successfully analyzed {}:{} with ID {}", 
        request.name, request.version, package_id);

    let full_json = serde_json::to_value(&analysis).unwrap_or(serde_json::json!({}));

    Ok(ResponseJson(AnalyzeResponse {
        success: true,
        package_id: Some(package_id),
        message: format!("Package {}:{} analyzed successfully", request.name, request.version),
        full_analysis: Some(full_json),
    }))
}

// ---------------- Fetch package analysis ----------------

pub async fn fetch_package_analysis(
    State(app_state): State<AppState>,
    Extension(_api_key): Extension<ApiKeyRecord>,
    Path(package_id): Path<Uuid>,
) -> Result<ResponseJson<serde_json::Value>, StatusCode> {
    // Api key already validated by middleware; fetch analysis
    match app_state.pool.get_full_analysis(&package_id).await {
        Ok(Some(json)) => Ok(ResponseJson(json)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
} 