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
    models::{AnalyzeRequest, AnalyzeResponse, PackageAnalysis},
    package::PackageAnalyzer,
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
    let extraction_depth = match api_key.tier.as_str() {
        "professional" => "full",
        "enterprise" => "deep", 
        _ => "basic",
    };

    // Update the request's extraction_depth to match what we're using
    request.extraction_depth = extraction_depth.to_string();

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
    let analysis = match analyzer.analyze(&request, key_id, &extraction_depth).await {
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

    let filtered_analysis = filter_analysis_by_tier(&analysis, &api_key.tier);
    let filtered_json = serde_json::to_value(&filtered_analysis).unwrap_or(serde_json::json!({}));

    // Add debug logging
    tracing::info!("Tier: {}, Original analysis keys: {:?}", api_key.tier, 
        serde_json::to_value(&analysis).unwrap().as_object().map(|o| o.keys().collect::<Vec<_>>()));
    tracing::info!("Filtered analysis keys: {:?}", 
        filtered_json.as_object().map(|o| o.keys().collect::<Vec<_>>()));

    Ok(ResponseJson(AnalyzeResponse {
        success: true,
        package_id: Some(package_id),
        message: format!("Package {}:{} analyzed successfully", request.name, request.version),
        full_analysis: Some(filtered_json),
    }))
}

// ---------------- Fetch package analysis ----------------

pub async fn fetch_package_analysis(
    State(app_state): State<AppState>,
    Extension(api_key): Extension<ApiKeyRecord>,
    Path(package_id): Path<Uuid>,
) -> Result<ResponseJson<serde_json::Value>, StatusCode> {
    match app_state.pool.get_full_analysis(&package_id).await {
        Ok(Some(json)) => {
            // Parse the full analysis and filter by tier
            if let Ok(analysis) = serde_json::from_value::<PackageAnalysis>(json.clone()) {
                let filtered_analysis = filter_analysis_by_tier(&analysis, &api_key.tier);
                let filtered_json = serde_json::to_value(&filtered_analysis).unwrap_or(json);
                Ok(ResponseJson(filtered_json))
            } else {
                Ok(ResponseJson(json)) // Fallback to unfiltered if parsing fails
            }
        },
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn filter_analysis_by_tier(analysis: &PackageAnalysis, tier: &str) -> PackageAnalysis {
    match tier {
        "basic" => {
            // Basic: Only crate metadata
            PackageAnalysis {
                key_modules: serde_json::json!([]),
                important_structs: serde_json::json!([]),
                notable_functions: serde_json::json!([]),
                traits: serde_json::json!([]),
                api_usage_examples: serde_json::json!([]),
                cargo_audit_report: serde_json::json!([]),
                unsafe_usage_locations: serde_json::json!([]),
                known_cve_references: serde_json::json!([]),
                docs_quality_score: serde_json::json!([]),
                dependency_graph: serde_json::json!([]),
                licenses: serde_json::json!([]),
                // Keep: package_name, version, description, repository, homepage, 
                // documentation, downloads, licenses, dependency_graph, cargo_toml
                ..analysis.clone()
            }
        },
        "professional" => {
            // Professional: Metadata + LLM enrichments + interface insights + basic security
            PackageAnalysis {
                unsafe_usage_locations: serde_json::json!([]),
                known_cve_references: serde_json::json!([]),
                dependency_graph: serde_json::json!([]),
                ..analysis.clone()
            }
        },
        "enterprise" => {
            // Enterprise: Everything including deep security analysis
            analysis.clone()
        },
        _ => {
            // Default to basic
            filter_analysis_by_tier(analysis, "basic")
        }
    }
} 