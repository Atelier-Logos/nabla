use anyhow::Result;
use home::home_dir;
use once_cell::sync::Lazy;
use serde::Serialize;
use serde_json::Value;
use std::{fs::File, io::BufReader, path::PathBuf};

use super::BinaryAnalysis;

const CVE_JSON_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

fn get_cve_cache_path() -> Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    let nabla_dir = home.join(".nabla");
    
    if !nabla_dir.exists() {
        std::fs::create_dir_all(&nabla_dir)?;
    }
    
    Ok(nabla_dir.join("cve_cache.json"))
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityMatch {
    pub cve_id: String,
    pub description: String,
    pub matched_keyword: String,
}

pub struct CveEntry {
    id: String,
    description: String,
    cpes: Vec<String>,
}

// Lazily-loaded CVE database so we incur the cost only once per process.
static CVE_DB: Lazy<Vec<CveEntry>> = Lazy::new(|| match load_cve_db() {
    Ok(db) => {
        tracing::info!("Loaded {} CVE records", db.len());
        db
    }
    Err(e) => {
        tracing::error!("Failed to load CVE DB: {}", e);
        Vec::new()
    }
});

pub fn load_cve_db() -> Result<Vec<CveEntry>> {
    let cache_path = get_cve_cache_path()?;
    
    // Try to load from cache first
    if cache_path.exists() {
        if let Ok(file) = File::open(&cache_path) {
            let reader = BufReader::new(file);
            if let Ok(v) = serde_json::from_reader::<_, Value>(reader) {
                tracing::info!("Loading CVE database from cache: {}", cache_path.display());
                return parse_cve_json(v);
            }
        }
    }
    
    // If cache doesn't exist or is invalid, download from NVD
    tracing::info!("Downloading CVE database from NVD (this may take a moment)...");
    download_and_cache_cve_db(cache_path)
}

fn download_and_cache_cve_db(cache_path: PathBuf) -> Result<Vec<CveEntry>> {
    // For now, use a simplified approach - download recent CVEs only
    // In production, you might want to download the full database or use incremental updates
    let response = ureq::get(CVE_JSON_URL)
        .query("resultsPerPage", "2000") // Limit to most recent 2000 CVEs to keep size manageable
        .call()
        .map_err(|e| anyhow::anyhow!("Failed to download CVE data: {}", e))?;
    
    let v: Value = response.into_json()
        .map_err(|e| anyhow::anyhow!("Failed to parse CVE JSON: {}", e))?;
    
    // Cache the downloaded data
    if let Ok(file) = std::fs::File::create(&cache_path) {
        let _ = serde_json::to_writer(file, &v);
        tracing::info!("Cached CVE database to: {}", cache_path.display());
    }
    
    parse_cve_json(v)
}

fn parse_cve_json(v: Value) -> Result<Vec<CveEntry>> {
    let mut entries = Vec::new();
    
    // Handle both old format (CVE_Items) and new NVD API 2.0 format (vulnerabilities)
    let items = if let Some(items) = v.get("CVE_Items").and_then(|x| x.as_array()) {
        // Old format
        items
    } else if let Some(items) = v.get("vulnerabilities").and_then(|x| x.as_array()) {
        // New NVD API 2.0 format
        items
    } else {
        return Ok(entries);
    };

    for item in items {
        // Handle both old and new formats
        let (id, description) = if let Some(cve) = item.get("cve") {
            // New format
            let id = cve.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
            let description = cve
                .get("descriptions")
                .and_then(|arr| arr.as_array())
                .and_then(|arr| arr.iter().find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en")))
                .and_then(|d| d.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (id, description)
        } else {
            // Old format fallback
            let id = item
                .get("cve")
                .and_then(|c| c.get("CVE_data_meta"))
                .and_then(|m| m.get("ID"))
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let description = item
                .get("cve")
                .and_then(|c| c.get("description"))
                .and_then(|d| d.get("description_data"))
                .and_then(|arr| arr.as_array())
                .and_then(|arr| arr.first())
                .and_then(|d| d.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (id, description)
        };

        // Collect CPEs
        let mut cpes = Vec::new();
        if let Some(configs) = item.get("configurations").and_then(|c| c.get("nodes")) {
            collect_cpes(configs, &mut cpes);
        }

        entries.push(CveEntry {
            id,
            description,
            cpes,
        });
    }
    Ok(entries)
}

pub fn collect_cpes(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Array(arr) => {
            for v in arr {
                collect_cpes(v, out);
            }
        }
        Value::Object(map) => {
            if let Some(cpe_matches) = map.get("cpe_match") {
                if let Some(arr) = cpe_matches.as_array() {
                    for cm in arr {
                        if let Some(uri) = cm.get("cpe23Uri").and_then(|u| u.as_str()) {
                            out.push(uri.to_lowercase());
                        }
                    }
                }
            }
            // Recurse into children nodes if present
            if let Some(children) = map.get("children") {
                collect_cpes(children, out);
            }
        }
        _ => {}
    }
}

/// Scan a `BinaryAnalysis` for potential vulnerabilities by matching linked libraries and import names
/// against the locally cached NVD CVE database.
pub fn scan_binary_vulnerabilities(analysis: &BinaryAnalysis) -> Vec<VulnerabilityMatch> {
    let mut keywords: Vec<String> = analysis
        .linked_libraries
        .iter()
        .chain(analysis.imports.iter())
        .map(|s| s.to_lowercase())
        .collect();

    // Add CPE candidates from metadata
    if let Some(cpe_candidates) = analysis
        .metadata
        .get("cpe_candidates")
        .and_then(|c| c.as_array())
    {
        keywords.extend(
            cpe_candidates
                .iter()
                .filter_map(|c| c.as_str().map(|s| s.to_string())),
        );
    }

    let mut matches = Vec::new();

    for entry in CVE_DB.iter() {
        for kw in &keywords {
            if kw.is_empty() {
                continue;
            }
            if entry.description.to_lowercase().contains(kw)
                || entry.cpes.iter().any(|c| c.contains(kw))
            {
                matches.push(VulnerabilityMatch {
                    cve_id: entry.id.clone(),
                    description: entry.description.clone(),
                    matched_keyword: kw.clone(),
                });
                break;
            }
        }
    }

    matches
}
