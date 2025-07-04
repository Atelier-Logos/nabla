use anyhow::Result;
use serde_json::Value as JsonValue;
use std::path::Path;
use tokio::process::Command;
use which::which;
use std::os::unix::fs::PermissionsExt;
use tokio::fs;

pub struct LicenseAnalysis {
    pub licenses: JsonValue,
}

pub async fn analyze(package_path: &Path) -> Result<LicenseAnalysis> {
    tracing::debug!("Running license analysis on {:?}", package_path);

    // Install cargo-license if not present
    ensure_cargo_license_installed().await?;
    
    // Run cargo-license
    let cargo_license_result = run_cargo_license(package_path).await;
    
    // Also check for license files
    let license_files = find_license_files(package_path).await;
    
    // Parse Cargo.toml for license information
    let cargo_toml_license = parse_cargo_toml_license(package_path).await;

    let mut licenses = serde_json::Map::new();
    
    if let Ok(license_output) = cargo_license_result {
        licenses.insert("cargo_license_output".to_string(), JsonValue::String(license_output));
    }
    
    licenses.insert("license_files".to_string(), JsonValue::Array(license_files));
    
    if let Some(toml_license) = cargo_toml_license {
        licenses.insert("cargo_toml_license".to_string(), JsonValue::String(toml_license));
    }

    Ok(LicenseAnalysis {
        licenses: JsonValue::Object(licenses),
    })
}

const CARGO_LICENSE_URL: &str = "https://github.com/onur/cargo-license/archive/refs/tags/v0.6.1.tar.gz";

async fn download_prebuilt_tool(url: &str, binary_name: &str) -> Result<()> {
    let home_dir = home::home_dir().ok_or_else(|| anyhow::anyhow!("Home directory not found"))?;
    let bin_dir = home_dir.join(".cargo").join("bin");
    fs::create_dir_all(&bin_dir).await?;

    let response = reqwest::get(url).await?;
    if !response.status().is_success() {
        anyhow::bail!("Failed to download {}: HTTP {}", binary_name, response.status());
    }

    let bytes = response.bytes().await?;
    let archive_path = bin_dir.join(format!("{}.tgz", binary_name));
    fs::write(&archive_path, &bytes).await?;

    // Extract
    let output = Command::new("tar")
        .args(["-xzf", archive_path.to_str().unwrap(), "-C", bin_dir.to_str().unwrap()])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("Failed to extract {}: {}", binary_name, String::from_utf8_lossy(&output.stderr));
    }

    // Ensure executable permission (binary might be inside a directory, try to find it)
    let mut entries = fs::read_dir(&bin_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.file_name().and_then(|s| s.to_str()).map(|s| s.starts_with(binary_name)).unwrap_or(false) {
            let mut perms = fs::metadata(&path).await?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).await?;
        }
    }

    let _ = fs::remove_file(&archive_path).await;
    Ok(())
}

async fn ensure_cargo_license_installed() -> Result<()> {
    if which("cargo-license").is_ok() {
        tracing::debug!("cargo-license is already installed");
        return Ok(());
    }

    tracing::info!("Attempting to download prebuilt cargo-license binary...");
    if let Err(e) = download_prebuilt_tool(CARGO_LICENSE_URL, "cargo-license").await {
        tracing::warn!("Prebuilt download failed: {}. Falling back to cargo install.", e);

        let install_output = Command::new("cargo")
            .args(["install", "cargo-license"])
            .output()
            .await?;

        if !install_output.status.success() {
            tracing::warn!("Failed to install cargo-license: {}", String::from_utf8_lossy(&install_output.stderr));
            // Don't fail analysis if install fails
        }
    }

    Ok(())
}

async fn run_cargo_license(package_path: &Path) -> Result<String> {
    // Run with --avoid-build-deps to skip building deps and cap runtime to 30s
    let cmd_fut = Command::new("cargo")
        .args(["license", "--json", "--avoid-build-deps"])
        .current_dir(package_path)
        .output();

    let output = match tokio::time::timeout(std::time::Duration::from_secs(30), cmd_fut).await {
        Ok(res) => res?,
        Err(_) => anyhow::bail!("cargo-license timed out after 30s")
    };

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        anyhow::bail!("cargo-license failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

async fn find_license_files(package_path: &Path) -> Vec<JsonValue> {
    let mut license_files = Vec::new();
    
    // Common license file names
    let license_filenames = [
        "LICENSE", "LICENSE.txt", "LICENSE.md",
        "COPYING", "COPYING.txt", "COPYING.md",
        "LICENSE-MIT", "LICENSE-APACHE",
        "LICENCE", "LICENCE.txt", "LICENCE.md"
    ];

    for filename in &license_filenames {
        let file_path = package_path.join(filename);
        if file_path.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&file_path).await {
                // Truncate very long license files for storage
                let content = if content.len() > 5000 {
                    format!("{}...[truncated]", &content[..5000])
                } else {
                    content
                };

                license_files.push(serde_json::json!({
                    "filename": filename,
                    "path": file_path.to_string_lossy(),
                    "content": content,
                    "size": content.len()
                }));
            }
        }
    }

    license_files
}

async fn parse_cargo_toml_license(package_path: &Path) -> Option<String> {
    let cargo_toml_path = package_path.join("Cargo.toml");
    
    if let Ok(content) = tokio::fs::read_to_string(cargo_toml_path).await {
        if let Ok(toml_value) = toml::from_str::<toml::Value>(&content) {
            // Check for license field in [package] section
            if let Some(package) = toml_value.get("package") {
                if let Some(license) = package.get("license") {
                    return license.as_str().map(|s| s.to_string());
                }
            }
        }
    }
    
    None
} 