use super::BinaryAnalysis;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use uuid::Uuid;
use chrono::{Utc, NaiveDate};

pub fn generate_sbom(analysis: &BinaryAnalysis) -> anyhow::Result<Value> {
    let serial_number = format!("urn:uuid:{}", Uuid::new_v4());
    let main_component_ref = format!("component-{}", analysis.id);

    // Base main component info
    let mut main_component = json!({
        "type": "application",
        "bom-ref": main_component_ref,
        "name": analysis.file_name,
        "version": analysis.version_info.as_ref()
            .and_then(|v| v.file_version.as_ref())
            .unwrap_or(&"unknown".to_string())
    });

    // Hashes (at least SHA-256)
    let mut hashes = vec![json!({
        "alg": "SHA-256",
        "content": analysis.hash_sha256
    })];
    if let Some(blake3_hash) = &analysis.hash_blake3 {
        hashes.push(json!({
            "alg": "BLAKE3",
            "content": blake3_hash
        }));
    }
    main_component["hashes"] = json!(hashes);

    // Optional license info
    if let Some(license_info) = &analysis.license_info {
        if !license_info.licenses.is_empty() {
            let licenses: Vec<Value> = license_info.licenses.iter()
                .map(|license| json!({"license": {"id": license}}))
                .collect();
            main_component["licenses"] = json!(licenses);
        }
    }

    // Optional supplier/vendor
    if let Some(version_info) = &analysis.version_info {
        if let Some(company) = &version_info.company {
            main_component["supplier"] = json!({ "name": company });
        }
    }

    // Description and properties
    main_component["description"] = json!(format!(
        "Binary component: {} ({})", 
        analysis.file_name, 
        analysis.format
    ));

    let mut properties = vec![
        json!({"name": "architecture", "value": analysis.architecture}),
        json!({"name": "format", "value": analysis.format}),
        json!({"name": "size_bytes", "value": analysis.size_bytes.to_string()}),
        json!({"name": "static_linked", "value": analysis.static_linked.to_string()}),
    ];

    if !analysis.languages.is_empty() {
        properties.push(json!({"name": "languages", "value": analysis.languages.join(",")}));
    }

    if let Some(version_info) = &analysis.version_info {
        properties.push(json!({"name": "version_confidence", "value": if version_info.confidence == 0.0 { "unknown".to_string() } else { version_info.confidence.to_string() }}));
    }
    if let Some(license_info) = &analysis.license_info {
        properties.push(json!({"name": "license_confidence", "value": if license_info.confidence == 0.0 { "unknown".to_string() } else { license_info.confidence.to_string() }}));
    }

    main_component["properties"] = json!(properties);

    // Components for linked libraries + imports
    let mut components = Vec::new();

    for (i, library) in analysis.linked_libraries.iter().enumerate() {
        components.push(json!({
            "type": "library",
            "bom-ref": format!("lib-{}", i),
            "name": library,
            "version": "unknown",
            "description": format!("Linked library: {}", library),
            "scope": "required"
        }));
    }

    for (i, import) in analysis.imports.iter().enumerate() {
        if analysis.linked_libraries.contains(import) {
            continue;
        }

        let (module_name, function_name) = if import.contains("::") {
            let parts: Vec<&str> = import.splitn(2, "::").collect();
            (parts[0].to_string(), Some(parts[1].to_string()))
        } else {
            (import.clone(), None)
        };

        let description = if let Some(func) = function_name.as_ref() {
            format!("Imported function: {}::{}", module_name, func)
        } else {
            format!("Imported module: {}", module_name)
        };

        components.push(json!({
            "type": "library",
            "bom-ref": if let Some(func) = function_name.as_ref() {
                format!("import-{}-{}-{}", i, module_name, func)
            } else {
                format!("import-{}-{}", i, module_name)
            },
            "name": if let Some(func) = function_name.as_ref() {
                format!("{}::{}", module_name, func)
            } else {
                module_name.clone()
            },
            "version": "unknown",
            "description": description,
            "scope": "required"
        }));
    }

    // Dependencies (main component depends on all libs + imports)
    let mut main_deps = Vec::new();

    for i in 0..analysis.linked_libraries.len() {
        main_deps.push(format!("lib-{}", i));
    }
    for i in 0..analysis.imports.len() {
        if !analysis.linked_libraries.contains(&analysis.imports[i]) {
            main_deps.push(format!("import-{}", i));
        }
    }

    let dependencies = if !main_deps.is_empty() {
        vec![json!({"ref": main_component_ref, "dependsOn": main_deps})]
    } else {
        Vec::new()
    };

    // Build final SBOM object
    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": analysis.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "tools": [{
                "vendor": "Atelier Logos LLC.",
                "name": "Nabla",
                "version": "0.1.0"
            }],
            "component": main_component
        },
        "components": components,
        "dependencies": dependencies
    });

    Ok(sbom)
}


fn extract_github_org(repository_url: &str) -> Option<String> {
    // Extract organization/user from GitHub URL
    // e.g., "https://github.com/rust-lang/cargo" -> "rust-lang"
    if repository_url.contains("github.com") {
        let parts: Vec<&str> = repository_url.split('/').collect();
        if parts.len() >= 5 {
            return Some(parts[3].to_string());
        }
    }
    None
}