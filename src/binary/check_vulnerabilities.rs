use once_cell::sync::Lazy;
use serde_json::Value;
use std::{fs::File, io::BufReader, path::Path};
use anyhow::Result;
use serde::Serialize;

use super::BinaryAnalysis;

const CVE_JSON_PATH: &str = "public/nvdcve-1.1-2025.json";

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
static CVE_DB: Lazy<Vec<CveEntry>> = Lazy::new(|| {
    match load_cve_db() {
        Ok(db) => {
            tracing::info!("Loaded {} CVE records", db.len());
            db
        }
        Err(e) => {
            tracing::error!("Failed to load CVE DB: {}", e);
            Vec::new()
        }
    }
});

pub fn load_cve_db() -> Result<Vec<CveEntry>> {
    let path = Path::new(CVE_JSON_PATH);
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let v: Value = serde_json::from_reader(reader)?;

    let mut entries = Vec::new();
    if let Some(items) = v.get("CVE_Items").and_then(|x| x.as_array()) {
        for item in items {
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

            // Collect cpe23Uris (may be nested)
            let mut cpes = Vec::new();
            if let Some(configs) = item.get("configurations").and_then(|c| c.get("nodes")) {
                collect_cpes(configs, &mut cpes);
            }

            entries.push(CveEntry { id, description, cpes });
        }
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
    let keywords: Vec<String> = analysis
        .linked_libraries
        .iter()
        .chain(analysis.imports.iter())
        .map(|s| s.to_lowercase())
        .collect();

    let mut matches = Vec::new();

    for entry in CVE_DB.iter() {
        // quick filter: see if any keyword is contained in description or cpe list
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
                break; // avoid duplicate matches for same entry
            }
        }
    }

    matches
}
