use anyhow::Result;
use flate2::read::GzDecoder;
use home::home_dir;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::{fs::File, io::BufReader, path::PathBuf};

use super::BinaryAnalysis;
use crate::enterprise::secure::control_flow::{ControlFlowGraph, ExploitabilityAnalysis};
use crate::enterprise::secure::{
    analyze_static_security, analyze_behavioral_security, 
    analyze_crypto_security, analyze_supply_chain_security
};

const CVE_BULK_DATA_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz";

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

#[derive(Debug, Clone, Serialize)]
pub struct EnterpriseVulnerabilityMatch {
    pub cve_id: String,
    pub description: String,
    pub matched_keyword: String,
    pub exploitability: ExploitabilityAnalysis,
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
    tracing::info!("Downloading complete CVE database from NVD bulk feed (this may take a few minutes)...");
    
    // Download the compressed CVE database
    let response = ureq::get(CVE_BULK_DATA_URL)
        .call()
        .map_err(|e| anyhow::anyhow!("Failed to download CVE bulk data: {}", e))?;
    
    // Read the gzip-compressed response
    let mut gz_decoder = GzDecoder::new(response.into_reader());
    let v: Value = serde_json::from_reader(&mut gz_decoder)
        .map_err(|e| anyhow::anyhow!("Failed to parse compressed CVE JSON: {}", e))?;
    
    // Cache the uncompressed data
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

/// Extract library keywords from embedded strings using pattern matching
fn extract_library_keywords_from_strings(embedded_strings: &[String]) -> Vec<String> {
    let mut keywords = Vec::new();
    
    for string in embedded_strings {
        let lower = string.to_lowercase();
        
        // Extract individual words that might be library names
        let words: Vec<&str> = lower.split_whitespace().collect();
        for word in &words {
            if is_potential_library_name(word) {
                keywords.push(word.to_string());
            }
        }
        
        // Look for version patterns like "name version" or "name-version"
        keywords.extend(extract_name_version_pairs(&lower));
        
        // Add words from the string that might be component names
        keywords.extend(extract_component_names(&lower));
    }
    
    keywords.sort();
    keywords.dedup();
    keywords
}

/// Check if a word could be a library/component name
fn is_potential_library_name(word: &str) -> bool {
    // Skip very short words, version numbers, and common non-library words
    if word.len() < 3 || word.chars().all(|c| c.is_numeric() || c == '.') {
        return false;
    }
    
    // Skip common non-library words
    let skip_words = ["the", "and", "for", "with", "this", "that", "from", "into", "version", "server", "web", "tool", "system"];
    if skip_words.contains(&word) {
        return false;
    }
    
    // Include words that look like library names (contain letters)
    word.chars().any(|c| c.is_alphabetic()) && word.len() <= 20
}

/// Extract "name version" pairs from strings
fn extract_name_version_pairs(s: &str) -> Vec<String> {
    let mut pairs = Vec::new();
    
    // Use regex to find patterns like "openssl 1.0.2a" or "libname-1.2.3"
    
    // Pattern for "name version" (name followed by version number)
    if let Ok(re) = Regex::new(r"([a-zA-Z][a-zA-Z0-9_-]*)\s+([0-9]+\.[0-9]+[a-zA-Z0-9.-]*)") {
        for cap in re.captures_iter(s) {
            if let (Some(name), Some(_version)) = (cap.get(1), cap.get(2)) {
                pairs.push(name.as_str().to_lowercase());
            }
        }
    }
    
    // Pattern for "name-version" (name hyphenated with version)
    if let Ok(re) = Regex::new(r"([a-zA-Z][a-zA-Z0-9_]*)-([0-9]+\.[0-9]+[a-zA-Z0-9.-]*)") {
        for cap in re.captures_iter(s) {
            if let (Some(name), Some(_version)) = (cap.get(1), cap.get(2)) {
                pairs.push(name.as_str().to_lowercase());
            }
        }
    }
    
    pairs
}

/// Extract component names from strings
fn extract_component_names(s: &str) -> Vec<String> {
    let mut components = Vec::new();
    
    // Split on various delimiters and collect meaningful words
    for delimiter in [" ", "-", "_", "/", "\\", ":", ";"] {
        for part in s.split(delimiter) {
            let cleaned = part.trim_matches(|c: char| !c.is_alphanumeric());
            if is_potential_library_name(cleaned) {
                components.push(cleaned.to_lowercase());
            }
        }
    }
    
    components
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

    // Extract library names and versions from embedded strings
    keywords.extend(extract_library_keywords_from_strings(&analysis.embedded_strings));

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

/// Enterprise-level vulnerability scanning with comprehensive security analysis.
pub fn enterprise_scan_binary_vulnerabilities(
    analysis: &BinaryAnalysis,
) -> Vec<EnterpriseVulnerabilityMatch> {
    let mut matches = Vec::new();
    
    // Build control flow graph for exploitability analysis
    let cfg = ControlFlowGraph::build_from_analysis(analysis);

    // Define sources for exploitability analysis (e.g., network-related imports)
    let sources: Vec<String> = analysis
        .imports
        .iter()
        .filter(|i| i.contains("recv") || i.contains("read") || i.contains("socket"))
        .cloned()
        .collect();

    // Run comprehensive enterprise security analysis
    let _static_results = analyze_static_security(analysis);
    let _behavioral_results = analyze_behavioral_security(analysis);
    let _crypto_results = analyze_crypto_security(analysis);
    let _supply_chain_results = analyze_supply_chain_security(analysis);

    // Get regular CVE matches and enhance with exploitability analysis
    let regular_matches = scan_binary_vulnerabilities(analysis);

    for match_item in regular_matches {
        let exploitability = if let Ok(cfg_ok) = &cfg {
            // Use the advanced control flow analysis for exploitability
            ExploitabilityAnalysis::analyze(cfg_ok, &sources, &match_item.matched_keyword)
        } else {
            // Fallback exploitability analysis if CFG build fails
            ExploitabilityAnalysis {
                is_reachable: false,
                path: None,
                sink: match_item.matched_keyword.clone(),
                confidence: 0.0,
                attack_vectors: vec![],
            }
        };

        matches.push(EnterpriseVulnerabilityMatch {
            cve_id: match_item.cve_id,
            description: match_item.description,
            matched_keyword: match_item.matched_keyword,
            exploitability,
        });
    }

    matches
}