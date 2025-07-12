use super::BinaryAnalysis;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    pub spdx_version: String,
    pub data_license: String,
    pub spdx_id: String,
    pub document_name: String,
    pub document_namespace: String,
    pub creators: Vec<String>,
    pub created: String,
    pub packages: Vec<SpdxPackage>,
    pub relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    pub spdx_id: String,
    pub name: String,
    pub download_location: String,
    pub files_analyzed: bool,
    pub checksums: Vec<SpdxChecksum>,
    pub copyright_text: String,
    pub license_concluded: String,
    pub license_declared: String,
    pub package_verification_code: Option<SpdxPackageVerificationCode>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxChecksum {
    pub algorithm: String,
    pub checksum_value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackageVerificationCode {
    pub package_verification_code_value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationship {
    pub spdx_element_id: String,
    pub related_spdx_element: String,
    pub relationship_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxDocument {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: i32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
    pub dependencies: Vec<CycloneDxDependency>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxMetadata {
    pub timestamp: String,
    pub tools: Vec<CycloneDxTool>,
    pub component: CycloneDxComponent,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub bom_ref: String,
    pub name: String,
    pub version: Option<String>,
    pub hashes: Option<Vec<CycloneDxHash>>,
    pub licenses: Option<Vec<CycloneDxLicense>>,
    pub copyright: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxLicense {
    pub license: CycloneDxLicenseChoice,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxLicenseChoice {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxDependency {
    #[serde(rename = "ref")]
    pub dependency_ref: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SbomFormat {
    Spdx,
    CycloneDx,
}

pub fn generate_sbom(analysis: &BinaryAnalysis, format: SbomFormat) -> anyhow::Result<serde_json::Value> {
    match format {
        SbomFormat::Spdx => generate_spdx_sbom(analysis),
        SbomFormat::CycloneDx => generate_cyclonedx_sbom(analysis),
    }
}

fn generate_spdx_sbom(analysis: &BinaryAnalysis) -> anyhow::Result<serde_json::Value> {
    let document_id = format!("SPDXRef-DOCUMENT-{}", analysis.id);
    let package_id = format!("SPDXRef-Package-{}", analysis.file_name.replace(".", "-"));
    
    let mut checksums = vec![
        SpdxChecksum {
            algorithm: "SHA256".to_string(),
            checksum_value: analysis.hash_sha256.clone(),
        }
    ];
    
    if let Some(blake3_hash) = &analysis.hash_blake3 {
        checksums.push(SpdxChecksum {
            algorithm: "BLAKE3".to_string(),
            checksum_value: blake3_hash.clone(),
        });
    }

    let main_package = SpdxPackage {
        spdx_id: package_id.clone(),
        name: analysis.file_name.clone(),
        download_location: "NOASSERTION".to_string(),
        files_analyzed: false,
        checksums,
        copyright_text: "NOASSERTION".to_string(),
        license_concluded: "NOASSERTION".to_string(),
        license_declared: "NOASSERTION".to_string(),
        package_verification_code: None,
    };

    let mut packages = vec![main_package];
    let mut relationships = vec![
        SpdxRelationship {
            spdx_element_id: document_id.clone(),
            related_spdx_element: package_id.clone(),
            relationship_type: "DESCRIBES".to_string(),
        }
    ];

    // Add linked libraries as packages
    for (i, lib) in analysis.linked_libraries.iter().enumerate() {
        let lib_id = format!("SPDXRef-Package-Library-{}", i);
        packages.push(SpdxPackage {
            spdx_id: lib_id.clone(),
            name: lib.clone(),
            download_location: "NOASSERTION".to_string(),
            files_analyzed: false,
            checksums: vec![],
            copyright_text: "NOASSERTION".to_string(),
            license_concluded: "NOASSERTION".to_string(),
            license_declared: "NOASSERTION".to_string(),
            package_verification_code: None,
        });

        relationships.push(SpdxRelationship {
            spdx_element_id: package_id.clone(),
            related_spdx_element: lib_id,
            relationship_type: "DEPENDS_ON".to_string(),
        });
    }

    let document = SpdxDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdx_id: document_id,
        document_name: format!("SBOM for {}", analysis.file_name),
        document_namespace: format!("https://ferropipe-audit.com/sbom/{}", analysis.id),
        creators: vec![
            "Tool: ferropipe-audit".to_string(),
            format!("Organization: Generated at {}", analysis.created_at.format("%Y-%m-%dT%H:%M:%SZ")),
        ],
        created: analysis.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        packages,
        relationships,
    };

    Ok(serde_json::to_value(document)?)
}

fn generate_cyclonedx_sbom(analysis: &BinaryAnalysis) -> anyhow::Result<serde_json::Value> {
    let serial_number = format!("urn:uuid:{}", Uuid::new_v4());
    let main_component_ref = format!("component-{}", analysis.file_name.replace(".", "-"));
    
    let mut hashes = vec![
        CycloneDxHash {
            alg: "SHA-256".to_string(),
            content: analysis.hash_sha256.clone(),
        }
    ];
    
    if let Some(blake3_hash) = &analysis.hash_blake3 {
        hashes.push(CycloneDxHash {
            alg: "BLAKE3".to_string(),
            content: blake3_hash.clone(),
        });
    }

    let main_component = CycloneDxComponent {
        component_type: "application".to_string(),
        bom_ref: main_component_ref.clone(),
        name: analysis.file_name.clone(),
        version: Some("unknown".to_string()),
        hashes: Some(hashes),
        licenses: Some(vec![CycloneDxLicense {
            license: CycloneDxLicenseChoice {
                id: None,
                name: Some("Unknown".to_string()),
            }
        }]),
        copyright: Some("Unknown".to_string()),
        description: Some(format!("Binary analysis of {} ({})", analysis.file_name, analysis.format)),
    };

    let mut components = Vec::new();
    let mut dependencies = vec![CycloneDxDependency {
        dependency_ref: main_component_ref.clone(),
        depends_on: Vec::new(),
    }];

    // Add linked libraries as components
    for (i, lib) in analysis.linked_libraries.iter().enumerate() {
        let lib_ref = format!("library-{}", i);
        components.push(CycloneDxComponent {
            component_type: "library".to_string(),
            bom_ref: lib_ref.clone(),
            name: lib.clone(),
            version: Some("unknown".to_string()),
            hashes: None,
            licenses: Some(vec![CycloneDxLicense {
                license: CycloneDxLicenseChoice {
                    id: None,
                    name: Some("Unknown".to_string()),
                }
            }]),
            copyright: Some("Unknown".to_string()),
            description: Some(format!("Linked library: {}", lib)),
        });

        // Add dependency relationship
        if let Some(main_dep) = dependencies.iter_mut().find(|d| d.dependency_ref == main_component_ref) {
            main_dep.depends_on.push(lib_ref);
        }
    }

    let metadata = CycloneDxMetadata {
        timestamp: analysis.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        tools: vec![CycloneDxTool {
            vendor: "Ferropipe".to_string(),
            name: "ferropipe-audit".to_string(),
            version: "0.1.0".to_string(),
        }],
        component: main_component,
    };

    let document = CycloneDxDocument {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.4".to_string(),
        serial_number,
        version: 1,
        metadata,
        components,
        dependencies,
    };

    Ok(serde_json::to_value(document)?)
}

// Helper function to detect license from binary content/metadata
fn detect_license_from_strings(strings: &[String]) -> String {
    let license_indicators = [
        ("MIT", vec!["MIT License", "MIT license"]),
        ("Apache-2.0", vec!["Apache License", "Apache-2.0"]),
        ("GPL-3.0", vec!["GNU General Public License", "GPL"]),
        ("BSD", vec!["BSD License", "BSD"]),
        ("ISC", vec!["ISC License"]),
    ];

    for string in strings {
        for (license, indicators) in &license_indicators {
            for indicator in indicators {
                if string.contains(indicator) {
                    return license.to_string();
                }
            }
        }
    }

    "Unknown".to_string()
}

// Helper function to extract version from filename or content
fn extract_version_from_filename(filename: &str) -> Option<String> {
    use regex::Regex;
    
    let version_regex = Regex::new(r"v?(\d+\.\d+(?:\.\d+)?)").ok()?;
    
    if let Some(captures) = version_regex.captures(filename) {
        return captures.get(1).map(|m| m.as_str().to_string());
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_analysis() -> BinaryAnalysis {
        BinaryAnalysis {
            id: Uuid::new_v4(),
            file_name: "test-binary.exe".to_string(),
            format: "pe".to_string(),
            architecture: "x86_64".to_string(),
            languages: vec!["C++".to_string()],
            detected_symbols: vec!["main".to_string(), "printf".to_string()],
            embedded_strings: vec!["Hello World".to_string()],
            suspected_secrets: vec![],
            imports: vec!["kernel32.dll".to_string()],
            exports: vec!["main".to_string()],
            hash_sha256: "abcd1234".to_string(),
            hash_blake3: Some("efgh5678".to_string()),
            size_bytes: 1024,
            linked_libraries: vec!["msvcrt.dll".to_string(), "kernel32.dll".to_string()],
            static_linked: false,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            sbom: None,
        }
    }

    #[test]
    fn test_generate_spdx_sbom() {
        let analysis = create_test_analysis();
        let sbom = generate_spdx_sbom(&analysis);
        assert!(sbom.is_ok());
        
        let sbom_value = sbom.unwrap();
        assert!(sbom_value.get("spdxVersion").is_some());
        assert!(sbom_value.get("packages").is_some());
    }

    #[test]
    fn test_generate_cyclonedx_sbom() {
        let analysis = create_test_analysis();
        let sbom = generate_cyclonedx_sbom(&analysis);
        assert!(sbom.is_ok());
        
        let sbom_value = sbom.unwrap();
        assert!(sbom_value.get("bomFormat").is_some());
        assert!(sbom_value.get("components").is_some());
    }

    #[test]
    fn test_version_extraction() {
        assert_eq!(extract_version_from_filename("app-v1.2.3.exe"), Some("1.2.3".to_string()));
        assert_eq!(extract_version_from_filename("binary-2.0.exe"), Some("2.0".to_string()));
        assert_eq!(extract_version_from_filename("test.exe"), None);
    }
}
