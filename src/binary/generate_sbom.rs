use super::BinaryAnalysis;
use crate::models::PackageAnalysis;
use serde_json::{json, Value};
use uuid::Uuid;
use chrono::Utc;

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
                "vendor": "Ferropipe",
                "name": "ferropipe-audit",
                "version": "0.1.0"
            }],
            "component": main_component
        },
        "components": components,
        "dependencies": dependencies
    });

    Ok(sbom)
}

pub fn generate_package_sbom(analysis: &PackageAnalysis) -> anyhow::Result<Value> {
    let serial_number = format!("urn:uuid:{}", Uuid::new_v4());
    let package_id = Uuid::new_v4(); // Generate ID for the package
    let main_component_ref = format!("package-{}", package_id);

    // Extract license information from the JSON value
    let licenses = if let Some(license_array) = analysis.licenses.as_array() {
        license_array.iter()
            .filter_map(|l| l.as_str())
            .map(|license| json!({"license": {"id": license}}))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    // Create main component (the package itself)
    let mut main_component = json!({
        "type": "library",
        "bom-ref": main_component_ref,
        "name": analysis.package_name,
        "version": analysis.version,
        "description": analysis.description.as_ref().unwrap_or(&"No description available".to_string())
    });

    // Add license information if available
    if !licenses.is_empty() {
        main_component["licenses"] = json!(licenses);
    }

    // Add publisher/supplier if available (from repository info)
    if let Some(repository) = &analysis.repository {
        // Extract organization/user from GitHub URL
        if let Some(org) = extract_github_org(repository) {
            main_component["supplier"] = json!({
                "name": org
            });
        }
    }

    // Add external references
    let mut external_refs = Vec::new();
    
    if let Some(repository) = &analysis.repository {
        external_refs.push(json!({
            "type": "vcs",
            "url": repository
        }));
    }
    
    if let Some(homepage) = &analysis.homepage {
        external_refs.push(json!({
            "type": "website",
            "url": homepage
        }));
    }
    
    if let Some(documentation) = &analysis.documentation {
        external_refs.push(json!({
            "type": "documentation",
            "url": documentation
        }));
    }
    
    if !external_refs.is_empty() {
        main_component["externalReferences"] = json!(external_refs);
    }

    // Add properties for additional metadata
    let mut properties = Vec::new();
        properties.push(json!({"name": "uses_unsafe", "value": analysis.uses_unsafe.to_string()}));
    properties.push(json!({"name": "build_rs_present", "value": analysis.build_rs_present.to_string()}));
    properties.push(json!({"name": "public_api_surface", "value": analysis.public_api_surface.to_string()}));
    
    if let Some(downloads) = analysis.downloads {
        properties.push(json!({"name": "downloads", "value": downloads.to_string()}));
    }
    
    if let Some(publish_date) = analysis.publish_date {
        properties.push(json!({"name": "publish_date", "value": publish_date.format("%Y-%m-%d").to_string()}));
    }

    main_component["properties"] = json!(properties);

    // Create components for dependencies
    let mut components = Vec::new();
    
    // Add external crates as components
    for (i, external_crate) in analysis.external_crates_used.iter().enumerate() {
        let dep_component = json!({
            "type": "library",
            "bom-ref": format!("dep-{}", i),
            "name": external_crate,
            "version": "unknown",
            "description": format!("External dependency: {}", external_crate),
            "scope": "required"
        });
        components.push(dep_component);
    }

    // Create dependencies (relationships)
    let mut dependencies = Vec::new();
    let mut main_deps = Vec::new();
    
    // Main package depends on all external crates
    for i in 0..analysis.external_crates_used.len() {
        main_deps.push(format!("dep-{}", i));
    }
    
    if !main_deps.is_empty() {
        dependencies.push(json!({
            "ref": main_component_ref,
            "dependsOn": main_deps
        }));
    }

    // Build the complete SBOM
    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "tools": [{
                "vendor": "Ferropipe",
                "name": "ferropipe-audit",
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use crate::binary::{VersionInfo, LicenseInfo};

    fn create_test_analysis() -> BinaryAnalysis {
        BinaryAnalysis {
            id: Uuid::new_v4(),
            file_name: "test.exe".to_string(),
            format: "application/x-msdownload".to_string(),
            architecture: "x86_64".to_string(),
            languages: vec!["C++".to_string()],
            detected_symbols: vec![],
            embedded_strings: vec![],
            suspected_secrets: vec![],
            imports: vec!["kernel32.dll::CreateFileW".to_string()],
            exports: vec!["main".to_string()],
            hash_sha256: "abc123".to_string(),
            hash_blake3: Some("def456".to_string()),
            size_bytes: 1024,
            linked_libraries: vec!["kernel32.dll".to_string()],
            static_linked: false,
            version_info: Some(VersionInfo {
                version_strings: vec!["1.0.0".to_string()],
                file_version: Some("1.0.0".to_string()),
                product_version: None,
                company: Some("Test Corp".to_string()),
                product_name: Some("Test App".to_string()),
                confidence: 0.8,
            }),
            license_info: Some(LicenseInfo {
                licenses: vec!["MIT".to_string()],
                copyright_notices: vec!["© 2024 Test Corp".to_string()],
                spdx_identifiers: vec!["MIT".to_string()],
                license_texts: vec![],
                confidence: 0.9,
            }),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            sbom: None,
        }
    }

    #[test]
    fn test_generate_sbom_vendor_and_supplier_extraction() {
        let analysis = create_test_analysis();
        let sbom = generate_sbom(&analysis).unwrap();
        
        // Check tool vendor (who made the analysis tool)
        assert_eq!(sbom["metadata"]["tools"][0]["vendor"], "Ferropipe");
        assert_eq!(sbom["metadata"]["tools"][0]["name"], "ferropipe-audit");
        
        // Check supplier (who made the analyzed binary)
        assert_eq!(sbom["metadata"]["component"]["supplier"]["name"], "Test Corp");
        
        // Check component properties
        assert_eq!(sbom["metadata"]["component"]["name"], "test.exe");
        assert_eq!(sbom["metadata"]["component"]["version"], "1.0.0");
        assert_eq!(sbom["metadata"]["component"]["type"], "application");
        
        // Check hashes are included
        let hashes = &sbom["metadata"]["component"]["hashes"];
        assert_eq!(hashes[0]["alg"], "SHA-256");
        assert_eq!(hashes[0]["content"], "abc123");
        assert_eq!(hashes[1]["alg"], "BLAKE3");
        assert_eq!(hashes[1]["content"], "def456");
        
        // Check license info
        assert_eq!(sbom["metadata"]["component"]["licenses"][0]["license"]["id"], "MIT");
        
        // Check components include linked libraries
        let components = &sbom["components"];
        assert_eq!(components[0]["name"], "kernel32.dll");
        assert_eq!(components[0]["type"], "library");
        assert_eq!(components[0]["scope"], "required");
        
        // Check dependencies are created
        let dependencies = &sbom["dependencies"];
        assert_eq!(dependencies[0]["ref"], format!("component-{}", analysis.id));
        assert!(dependencies[0]["dependsOn"].as_array().unwrap().contains(&serde_json::Value::String("lib-0".to_string())));
    }

    #[test]
    fn test_generate_sbom_without_optional_fields() {
        let mut analysis = create_test_analysis();
        analysis.version_info = None;
        analysis.license_info = None;
        analysis.hash_blake3 = None;
        
        let sbom = generate_sbom(&analysis).unwrap();
        
        // Should still generate valid SBOM
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.4");
        assert_eq!(sbom["metadata"]["component"]["version"], "unknown");
        
        // Should not have supplier field
        assert!(sbom["metadata"]["component"]["supplier"].is_null());
        
        // Should only have SHA-256 hash
        let hashes = &sbom["metadata"]["component"]["hashes"];
        assert_eq!(hashes.as_array().unwrap().len(), 1);
        assert_eq!(hashes[0]["alg"], "SHA-256");
    }
}