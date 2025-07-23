use regex::Regex;
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

use goblin::{elf::Elf, pe::PE};
use wasmparser::{Parser, Payload};

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

    let version_patterns = [
        Regex::new(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\b").unwrap(),
        Regex::new(r"\bv(\d+\.\d+\.\d+(?:\.\d+)?)\b").unwrap(),
        Regex::new(r"\bversion\s*[:=]\s*([^\s,;]+)").unwrap(),
        Regex::new(r"\bVERSION\s*[:=]\s*([^\s,;]+)").unwrap(),
        Regex::new(r"\b(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)\b").unwrap(),
    ];

    for string in strings {
        for pattern in &version_patterns {
            for captures in pattern.captures_iter(string) {
                if let Some(version) = captures.get(1) {
                    if is_valid_version(version.as_str()) {
                        version_strings.insert(version.as_str().to_string());
                    }
                }
            }
        }

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

    match format {
        "application/x-msdownload" => {
            if let Some(pe_version) = extract_pe_version_info(contents) {
                file_version = file_version.or(pe_version.file_version);
                product_version = product_version.or(pe_version.product_version);
                company = company.or(pe_version.company);
                product_name = product_name.or(pe_version.product_name);
            }
        }
        "application/x-elf" => {
            if let Some(elf_versions) = extract_elf_version_info(contents) {
                version_strings.extend(elf_versions);
            }
        }
        "application/x-mach-binary" => {
            if let Some(macho_versions) = extract_macho_version_info(contents) {
                version_strings.extend(macho_versions);
            }
        }
        "application/wasm" => {
            if let Some(wasm_versions) = extract_wasm_version_info(contents) {
                version_strings.extend(wasm_versions);
            }
        }
        _ => {}
    }

    if file_version.is_none() && !version_strings.is_empty() {
        file_version = version_strings.iter().max_by_key(|v| v.matches('.').count()).cloned();
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

    let license_patterns = [
        (Regex::new(r"(?i)\b(MIT|BSD|GPL|LGPL|Apache|Mozilla|ISC|Unlicense)\b").unwrap(), "identifier"),
        (Regex::new(r"(?i)licensed under the ([^.,;]+)").unwrap(), "phrase"),
        (Regex::new(r"(?i)license:\s*([^.,;\n]+)").unwrap(), "declaration"),
        (Regex::new(r"(?i)copyright\s+.*").unwrap(), "copyright"),
        (Regex::new(r"SPDX-License-Identifier:\s*([^\s]+)").unwrap(), "spdx"),
    ];

    let license_text_patterns = [
        Regex::new(r"(?i)permission is hereby granted.*").unwrap(),
        Regex::new(r"(?i)redistribution and use in source and binary forms.*").unwrap(),
        Regex::new(r"(?i)this program is free software.*").unwrap(),
        Regex::new(r"(?i)licensed under the apache license.*").unwrap(),
    ];

    for string in strings {
        if string.len() < 10 {
            continue;
        }

        for (pattern, kind) in &license_patterns {
            for captures in pattern.captures_iter(string) {
                match *kind {
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

        for pattern in &license_text_patterns {
            if pattern.is_match(string) && string.len() > 100 {
                license_texts.push(string.clone());
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

pub fn is_valid_version(version: &str) -> bool {
    if version.len() < 3 || version.len() > 20 || !version.contains('.') {
        return false;
    }

    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() > 5 {
        return false;
    }

    for part in parts {
        if let Ok(num) = part.parse::<u32>() {
            if num > 9999 {
                return false;
            }
        }
    }

    true
}

pub fn extract_company_name(string: &str) -> Option<String> {
    let patterns = [
        Regex::new(r"(?i)company:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)corporation:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)© \d{4}\s+([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)copyright.*?(\w+(?:\s+\w+){0,3})(?:\s+inc\.?|\s+corp\.?|\s+ltd\.?|\s+llc)").unwrap(),
    ];

    for pattern in &patterns {
        if let Some(caps) = pattern.captures(string) {
            if let Some(m) = caps.get(1) {
                let s = m.as_str().trim();
                if s.len() > 2 && s.len() < 100 {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

pub fn extract_product_name(string: &str) -> Option<String> {
    let patterns = [
        Regex::new(r"(?i)product:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)application:\s*([^.,;\n]+)").unwrap(),
        Regex::new(r"(?i)program:\s*([^.,;\n]+)").unwrap(),
    ];

    for pattern in &patterns {
        if let Some(caps) = pattern.captures(string) {
            if let Some(m) = caps.get(1) {
                let s = m.as_str().trim();
                if s.len() > 2 && s.len() < 100 {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

pub fn normalize_license_name(license: &str) -> String {
    match license.to_lowercase().as_str() {
        "mit" => "MIT".to_string(),
        "bsd" => "BSD".to_string(),
        "gpl" => "GPL".to_string(),
        "lgpl" => "LGPL".to_string(),
        "apache" => "Apache-2.0".to_string(),
        "mozilla" => "MPL-2.0".to_string(),
        "isc" => "ISC".to_string(),
        "unlicense" => "Unlicense".to_string(),
        other => other.to_string(),
    }
}

pub fn infer_license_from_text(text: &str) -> Option<String> {
    let t = text.to_lowercase();
    if t.contains("permission is hereby granted") && t.contains("mit") {
        Some("MIT".to_string())
    } else if t.contains("redistribution and use in source and binary forms") {
        Some("BSD".to_string())
    } else if t.contains("apache license") {
        Some("Apache-2.0".to_string())
    } else if t.contains("gnu general public license") {
        Some("GPL".to_string())
    } else {
        None
    }
}

pub fn calculate_version_confidence(version_strings: &HashSet<String>, file_version: &Option<String>) -> f64 {
    let mut confidence: f64 = 0.0;
    if !version_strings.is_empty() {
        confidence += 0.3;
    }
    if file_version.is_some() {
        confidence += 0.4;
    }
    if version_strings.len() == 1 {
        confidence += 0.3;
    } else if version_strings.len() > 1 {
        confidence += 0.1;
    }
    confidence.min(1.0)
}

pub fn calculate_license_confidence(licenses: &HashSet<String>, spdx: &HashSet<String>, texts: &[String]) -> f64 {
    let mut confidence: f64 = 0.0;
    if !spdx.is_empty() {
        confidence += 0.5;
    }
    if !licenses.is_empty() {
        confidence += 0.3;
    }
    if !texts.is_empty() {
        confidence += 0.2;
    }
    confidence.min(1.0)
}

// -----------------------------------------
// Format-specific extractors below
// -----------------------------------------

#[derive(Debug)]
pub struct PeVersionInfo {
    file_version: Option<String>,
    product_version: Option<String>,
    company: Option<String>,
    product_name: Option<String>,
}

pub fn extract_pe_version_info(contents: &[u8]) -> Option<PeVersionInfo> {
    // Use goblin to parse PE headers and extract basic version info from optional header
    if let Ok(pe) = PE::parse(contents) {
        if let Some(ref opt_header) = pe.header.optional_header {
            let windows = &opt_header.windows_fields;

            // File version: image version fields (if non-zero)
            let file_version = if windows.major_image_version != 0 || windows.minor_image_version != 0 {
                Some(format!("{}.{}", windows.major_image_version, windows.minor_image_version))
            } else {
                None
            };

            // Product version: subsystem version fields (if non-zero)
            let product_version = if windows.major_subsystem_version != 0 || windows.minor_subsystem_version != 0 {
                Some(format!("{}.{}", windows.major_subsystem_version, windows.minor_subsystem_version))
            } else {
                None
            };

            return Some(PeVersionInfo {
                file_version,
                product_version,
                company: None,        // Not available from headers
                product_name: None,   // Not available from headers
            });
        }
    }
    None
}

pub fn extract_elf_version_info(contents: &[u8]) -> Option<Vec<String>> {
    if let Ok(elf) = Elf::parse(contents) {
        let mut versions = Vec::new();
        if let Some(note_iter) = elf.iter_note_headers(contents) {
            for note_result in note_iter {
                if let Ok(n) = note_result {
                    if n.name == "GNU" && n.n_type == goblin::elf::note::NT_GNU_BUILD_ID {
                        let hex = n.desc.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        versions.push(hex);
                    }
                }
            }
        }
        Some(versions)
    } else {
        None
    }
}

pub fn extract_macho_version_info(_contents: &[u8]) -> Option<Vec<String>> {
    None // advanced Mach-O version extraction not implemented yet
}

pub fn extract_wasm_version_info(contents: &[u8]) -> Option<Vec<String>> {
    let mut versions = Vec::new();
    let parser = Parser::new(0);
    for payload in parser.parse_all(contents) {
        if let Ok(Payload::CustomSection(s)) = payload {
            if s.name().contains("version") || s.name().contains("meta") {
                let text = String::from_utf8_lossy(s.data());
                for line in text.lines() {
                    if let Some(v) = line.split_whitespace().find(|w| is_valid_version(w)) {
                        versions.push(v.to_string());
                    }
                }
            }
        }
    }
    Some(versions)
}
