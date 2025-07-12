use anyhow::Result;
use serde_json::Value as JsonValue;
use std::path::Path;
use tokio::process::Command;
use which::which;
use std::os::unix::fs::PermissionsExt;
use tokio::fs;

const CARGO_AUDIT_URL: &str = "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv0.21.2/cargo-audit-aarch64-unknown-linux-gnu-v0.21.2.tgz";

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

    // Ensure executable permission
    let bin_path = bin_dir.join(binary_name);
    let mut perms = fs::metadata(&bin_path).await?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bin_path, perms).await?;

    // Cleanup
    let _ = fs::remove_file(&archive_path).await;
    Ok(())
}

pub struct AuditResult {
    pub report: JsonValue,
    pub cve_references: JsonValue,
}

pub async fn analyze(package_path: &Path) -> Result<AuditResult> {
    tracing::debug!("Running cargo audit analysis on {:?}", package_path);

    // Install cargo-audit if not present
    ensure_cargo_audit_installed().await?;

    // Run cargo audit with JSON output
    let output = Command::new("cargo")
        .args(["audit", "--json", "--color", "never"])
        .current_dir(package_path)
        .output()
        .await?;

    let raw_output = String::from_utf8_lossy(&output.stdout);

    // cargo-audit may emit progress lines. Keep the first valid JSON line.
    let audit_output = raw_output
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or("")
        .to_string();

    let report = if audit_output.trim().is_empty() {
        serde_json::json!({
            "vulnerabilities": [],
            "warnings": [],
            "status": "no_vulnerabilities"
        })
    } else {
        // Parse the JSON output
        match serde_json::from_str::<JsonValue>(&audit_output) {
            Ok(json) => json,
            Err(_) => {
                // If JSON parsing fails, create a basic report
                serde_json::json!({
                    "vulnerabilities": [],
                    "warnings": [audit_output],
                    "status": "parse_error"
                })
            }
        }
    };

    // Extract CVE references
    let cve_references = extract_cve_references(&report);

    Ok(AuditResult {
        report,
        cve_references,
    })
}

async fn ensure_cargo_audit_installed() -> Result<()> {
    // Fast-path: if the binary is already present in common locations just return.
    // We explicitly check both /usr/local/bin and /usr/local/cargo/bin because
    // the Dockerfile copies the pre-built binary to one of these paths.
    let preinstalled_paths = ["/usr/local/bin/cargo-audit", "/usr/local/cargo/bin/cargo-audit"];
    if preinstalled_paths.iter().any(|p| std::path::Path::new(p).exists()) {
        tracing::debug!("cargo-audit binary already present at {:?}", preinstalled_paths);
        return Ok(());
    }

    if which("cargo-audit").is_ok() {
        tracing::debug!("cargo-audit is already installed");
        return Ok(());
    }

    // Try downloading prebuilt binary first
    tracing::info!("Attempting to download prebuilt cargo-audit binary...");
    if let Err(e) = download_prebuilt_tool(CARGO_AUDIT_URL, "cargo-audit").await {
        tracing::warn!("Prebuilt download failed: {}. Falling back to cargo install.", e);

        // Fallback to cargo install
        let install_output = Command::new("cargo")
            .args(["install", "cargo-audit"])
            .output()
            .await?;

        if !install_output.status.success() {
            anyhow::bail!("Failed to install cargo-audit: {}", String::from_utf8_lossy(&install_output.stderr));
        }
    }

    Ok(())
}

fn extract_cve_references(report: &JsonValue) -> JsonValue {
    let mut cve_refs = Vec::new();

    if let Some(list) = report
        .get("vulnerabilities")
        .and_then(|v| {
            if v.is_array() { Some(v) } else { v.get("list") }
        })
        .and_then(|v| v.as_array())
    {
        for vuln in list {
            // get advisory object or treat vuln itself as advisory
            let advisory = vuln.get("advisory").unwrap_or(vuln);

            if let Some(id_str) = advisory.get("id").and_then(|id| id.as_str()) {
                let include = id_str.starts_with("CVE-")
                    || id_str.starts_with("RUSTSEC-")
                    || id_str.starts_with("GHSA-");

                if include {
                        cve_refs.push(serde_json::json!({
                        "id": id_str,
                            "severity": advisory.get("severity").unwrap_or(&JsonValue::Null),
                            "title": advisory.get("title").unwrap_or(&JsonValue::Null),
                            "description": advisory.get("description").unwrap_or(&JsonValue::Null),
                            "affected_package": vuln.get("package").and_then(|p| p.get("name"))
                        }));
                }
            }
        }
    }

    JsonValue::Array(cve_refs)
} 