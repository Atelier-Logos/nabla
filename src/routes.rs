use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::Json as ResponseJson,
};
use serde_json::json;

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

pub async fn analyze_package(
    State(app_state): State<AppState>,
    Json(request): Json<AnalyzeRequest>,
) -> Result<ResponseJson<AnalyzeResponse>, (StatusCode, ResponseJson<AnalyzeResponse>)> {
    tracing::info!("Received analysis request for {}:{}", request.name, request.version);

    // Verify API key
    let key_id = match app_state.pool.verify_api_key(&request.api_key).await {
        Ok(Some(key_id)) => key_id,
        Ok(None) => {
            tracing::warn!("Invalid API key provided");
            return Err((
                StatusCode::UNAUTHORIZED,
                ResponseJson(AnalyzeResponse {
                    success: false,
                    package_id: None,
                    message: "Invalid API key".to_string(),
                })
            ));
        }
        Err(e) => {
            tracing::error!("Failed to verify API key: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(AnalyzeResponse {
                    success: false,
                    package_id: None,
                    message: "Database error".to_string(),
                })
            ));
        }
    };

    // Validate input parameters
    if request.name.is_empty() || request.version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(AnalyzeResponse {
                success: false,
                package_id: None,
                message: "Package name and version are required".to_string(),
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
                })
            ));
        }
    };

    tracing::info!("Successfully analyzed {}:{} with ID {}", 
        request.name, request.version, package_id);

    Ok(ResponseJson(AnalyzeResponse {
        success: true,
        package_id: Some(package_id),
        message: format!("Package {}:{} analyzed successfully", request.name, request.version),
    }))
} 