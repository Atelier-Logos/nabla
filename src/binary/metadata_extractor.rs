use regex::Regex;
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionInfo {
    pub version_strings: Vec<String>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub company: Option<String>,
    pub product_name: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseInfo {
    pub licenses: Vec<String>,
    pub copyright_notices: Vec<String>,
    pub spdx_identifiers: Vec<String>,
    pub license_texts: Vec<String>,
    pub confidence: f64,
}

pub fn extract_version_info(contents: &[u8], strings: &[String], format: &str) -> VersionInfo {
    let mut version_strings = HashSet::new();
    let mut file_version = None;
    let mut product_version = None;
    let mut company = None;
    let mut product_name = None;

    // Version regex patterns
    let version_patterns = [
        Regex::new(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\b").unwrap(),
        Regex::new(r"\bv(\d+\.\d+\.\d+(?:\.\d+)?)\b").unwrap(),
        Regex::new(r"\bversion\s*[:=]\s*([^\s,;]+)").unwrap(),
        Regex::new(r"\bVERSION\s*[:=]\s*([^\s,;]+)").unwrap(),
        Regex::new(r"\b(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)\b").unwrap(),
    ];

    // Extract from strings
    for string in strings {
        for pattern in &version_patterns {
            for captures in pattern.captures_iter(string) {
                if let Some(version) = captures.get(1) {
                    let version_str = version.as_str();
                    if is_valid_version(version_str) {
                        version_strings.insert(version_str.to_string());
                    }
                }
            }
        }

        // Look for company/product info
        if company.is_none() {
            if let Some(comp) = extract_company_name(string) {
                company = Some(comp);
            }
        }
        
        if product_name.is_none() {
            if let Some(prod) = extract_product_name(string) {
                product_name = Some(prod);
            }
        }
    }

    // Format-specific extraction
    match format {
        "application/x-msdownload" => {
            if let Some(pe_version) = extract_pe_version_info(contents) {
                if file_version.is_none() {
                    file_version = pe_version.file_version;
                }
                if product_version.is_none() {
                    product_version = pe_version.product_version;
                }
                if company.is_none() {
                    company = pe_version.company;
                }
                if product_name.is_none() {
                    product_name = pe_version.product_name;
                }
            }
        }
        "application/x-elf" => {
            if let Some(elf_version) = extract_elf_version_info(contents) {
                version_strings.extend(elf_version);
            }
        }
        "application/x-mach-binary" => {
            if let Some(macho_version) = extract_macho_version_info(contents) {
                version_strings.extend(macho_version);
            }
        }
        _ => {}
    }

    // Pick the most likely file version
    if file_version.is_none() && !version_strings.is_empty() {
        // Use the most "complete" looking version (most dots)
        file_version = version_strings.iter()
            .max_by_key(|v| v.matches('.').count())
            .cloned();
    }

    let confidence = calculate_version_confidence(&version_strings, &file_version);

    VersionInfo {
        version_strings: version_strings.into_iter().collect(),
        file_version,
        product_version,
        company,
        product_name,
        confidence,
    }
}

pub fn extract_license_info(strings: &[String]) -> LicenseInfo {
    let mut licenses = HashSet::new();
    let mut copyright_notices = Vec::new();
    let mut spdx_identifiers = HashSet::new();
    let mut license_texts = Vec::new();

    // License patterns
    let license_patterns = [
        (Regex::new(r"(?i)\b(MIT|BSD|GPL|LGPL|Apache|Mozilla|ISC|Unlicense)\b").unwrap(), "identifier"),
        (Regex::new(r"(?i)licensed under the ([^.,;]+)").unwrap(), "phrase"),
        (Regex::new(r"(?i)license:\s*([^.,;\n]+)").unwrap(), "declaration"),
        (Regex::new(r"(?i)copyright\s+.*").unwrap(), "copyright"),
        (Regex::new(r"SPDX-License-Identifier:\s*([^\s]+)").unwrap(), "spdx"),
    ];

    // Common license text patterns
    let license_text_patterns = [
        Regex::new(r"(?i)permission is hereby granted.*").unwrap(),
        Regex::new(r"(?i)redistribution and use in source and binary forms.*").unwrap(),
        Regex::new(r"(?i)this program is free software.*").unwrap(),
        Regex::new(r"(?i)licensed under the apache license.*").unwrap(),
    ];

    for string in strings {
        // Skip very short strings
        if string.len() < 10 {
            continue;
        }

        for (pattern, pattern_type) in &license_patterns {
            for captures in pattern.captures_iter(string) {
                match *pattern_type {
                    "identifier" | "phrase" | "declaration" => {
                        if let Some(license) = captures.get(1) {
                            let license_str = normalize_license_name(license.as_str());
                            if !license_str.is_empty() {
                                licenses.insert(license_str);
                            }
                        }
                    }
                    "copyright" => {
                        copyright_notices.push(string.clone());
                    }
                    "spdx" => {
                        if let Some(spdx) = captures.get(1) {
                            spdx_identifiers.insert(spdx.as_str().to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for license text
        for pattern in &license_text_patterns {
            if pattern.is_match(string) && string.len() > 100 {
                license_texts.push(string.clone());
                // Try to infer license from text
                if let Some(inferred) = infer_license_from_text(string) {
                    licenses.insert(inferred);
                }
            }
        }
    }

    let confidence = calculate_license_confidence(&licenses, &spdx_identifiers, &license_texts);

    LicenseInfo {
        licenses: licenses.into_iter().collect(),
        copyright_notices,
        spdx_identifiers: spdx_identifiers.into_iter().collect(),
        license_texts,
        confidence,
    }
}

fn is_valid_version(version: &str) -> bool {
    // Filter out false positives
    if version.len() < 3 || version.len() > 20 {
        return false;
    }
    
    // Must have at least one dot
    if !version.contains('.') {
        return false;
    }
    
    // Check if it looks like a version (not like a timestamp or IP)
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() > 5 {
        return false; // Too many parts
    }
    
    // Each part should be reasonable
    for part in parts {
        if let Ok(num) = part.parse::<u32>() {
            if num > 9999 { // Probably a timestamp or something else
                return false;
            }
        }
    }
    
    true
}

fn extract_company_name(string: &str) -> Option<String> {
    let company_patterns = [
        Regex::new(r"(?i)company:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)corporation:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)© \d{4}\s+([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)copyright.*?(\w+(?:\s+\w+){0,3})(?:\s+inc\.?|\s+corp\.?|\s+ltd\.?|\s+llc)").unwrap(),
    ];

    for pattern in &company_patterns {
        if let Some(captures) = pattern.captures(string) {
            if let Some(company) = captures.get(1) {
                let company_str = company.as_str().trim();
                if company_str.len() > 2 && company_str.len() < 100 {
                    return Some(company_str.to_string());
                }
            }
        }
    }
    None
}

fn extract_product_name(string: &str) -> Option<String> {
    let product_patterns = [
        Regex::new(r"(?i)product:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)application:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)program:\s*([^.,;\n]+)").unwrap(),
    ];

    for pattern in &product_patterns {
        if let Some(captures) = pattern.captures(string) {
            if let Some(product) = captures.get(1) {
                let product_str = product.as_str().trim();
                if product_str.len() > 2 && product_str.len() < 100 {
                    return Some(product_str.to_string());
                }
            }
        }
    }
    None
}

fn normalize_license_name(license: &str) -> String {
    let license_lower = license.to_lowercase();
    match license_lower.as_str() {
        "mit" => "MIT".to_string(),
        "bsd" => "BSD".to_string(),
        "gpl" => "GPL".to_string(),
        "lgpl" => "LGPL".to_string(),
        "apache" => "Apache-2.0".to_string(),
        "mozilla" => "MPL-2.0".to_string(),
        "isc" => "ISC".to_string(),
        "unlicense" => "Unlicense".to_string(),
        _ => license.to_string(),
    }
}

fn infer_license_from_text(text: &str) -> Option<String> {
    let text_lower = text.to_lowercase();
    
    if text_lower.contains("permission is hereby granted") && text_lower.contains("mit") {
        Some("MIT".to_string())
    } else if text_lower.contains("redistribution and use in source and binary forms") {
        Some("BSD".to_string())
    } else if text_lower.contains("apache license") {
        Some("Apache-2.0".to_string())
    } else if text_lower.contains("gnu general public license") {
        Some("GPL".to_string())
    } else {
        None
    }
}

fn calculate_version_confidence(version_strings: &HashSet<String>, file_version: &Option<String>) -> f64 {
    let mut confidence: f64 = 0.0;
    
    if !version_strings.is_empty() {
        confidence += 0.3;
    }
    
    if file_version.is_some() {
        confidence += 0.4;
    }
    
    // Higher confidence if we have multiple consistent versions
    if version_strings.len() == 1 {
        confidence += 0.3;
    } else if version_strings.len() > 1 {
        confidence += 0.1; // Multiple versions might be confusing
    }
    
    confidence.min(1.0)
}

fn calculate_license_confidence(licenses: &HashSet<String>, spdx: &HashSet<String>, texts: &[String]) -> f64 {
    let mut confidence: f64 = 0.0;
    
    if !spdx.is_empty() {
        confidence += 0.5; // SPDX identifiers are reliable
    }
    
    if !licenses.is_empty() {
        confidence += 0.3;
    }
    
    if !texts.is_empty() {
        confidence += 0.2;
    }
    
    confidence.min(1.0)
}

// Format-specific extractors (simplified for now)
struct PeVersionInfo {
    file_version: Option<String>,
    product_version: Option<String>,
    company: Option<String>,
    product_name: Option<String>,
}

fn extract_pe_version_info(_contents: &[u8]) -> Option<PeVersionInfo> {
    // TODO: Implement PE version resource parsing
    // This would parse VS_VERSION_INFO structures
    None
}

fn extract_elf_version_info(_contents: &[u8]) -> Option<Vec<String>> {
    // TODO: Implement ELF .note section parsing
    // Look for .note.gnu.build-id, .note.ABI-tag, etc.
    None
}

fn extract_macho_version_info(_contents: &[u8]) -> Option<Vec<String>> {
    // TODO: Implement Mach-O load command parsing
    // Look for LC_VERSION_MIN_*, LC_BUILD_VERSION
    None
}
