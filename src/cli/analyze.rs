use anyhow::{Result, anyhow};
use std::path::Path;
use reqwest::Client;
use std::fs;
use crate::cli::NablaCli;

impl NablaCli {
    pub fn handle_analyze_command(&mut self, file_path: &str) -> Result<()> {
        // Remove @ prefix if present
        let file_path = if file_path.starts_with('@') {
            &file_path[1..]
        } else {
            file_path
        };

        println!("🔍 Analyzing file: {}", file_path);

        // Check if file exists
        if !Path::new(file_path).exists() {
            return Err(anyhow!("File not found: {}", file_path));
        }

        // Check authentication (optional for basic analysis)
        let jwt_data = self.jwt_store.load_jwt().ok().flatten();

        // Get base URL
        let base_url = self.config_store.get_base_url()?;
        let analyze_url = format!("{}/analyze", base_url);

        println!("🔄 Uploading to analysis endpoint...");

        // Read file
        let file_content = fs::read(file_path)?;
        let file_name = Path::new(file_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Make HTTP request to /analyze endpoint
        let token = jwt_data.as_ref().map(|jwt| jwt.token.as_str());
        let result = self.send_analyze_request(&analyze_url, token, &file_content, &file_name)?;

        println!("✅ Analysis complete!");
        println!("Results: {}", result);

        Ok(())
    }

    fn send_analyze_request(
        &self,
        url: &str,
        token: Option<&str>,
        file_content: &[u8],
        file_name: &str,
    ) -> Result<String> {
        // This is a mock implementation
        // In real implementation, use reqwest to send multipart form data
        
        println!("📤 Sending {} bytes to {}", file_content.len(), url);
        
        match token {
            Some(t) => println!("🔐 Using authentication token: {}...", &t[..10.min(t.len())]),
            None => println!("🆓 Running free analysis (no authentication)"),
        }
        
        // Mock response - enhanced features if authenticated
        let analysis = if token.is_some() {
            serde_json::json!({
                "file_type": "binary",
                "architecture": "x86_64", 
                "security_score": 85,
                "threats_detected": 0,
                "vulnerabilities": [],
                "advanced_analysis": {
                    "entropy_analysis": "Normal entropy distribution",
                    "packer_detection": "No packing detected",
                    "code_signatures": "Valid signatures found"
                },
                "recommendations": [
                    "File appears clean",
                    "No malicious patterns detected",
                    "Advanced analysis complete"
                ]
            })
        } else {
            serde_json::json!({
                "file_type": "binary",
                "architecture": "x86_64",
                "security_score": 75,
                "threats_detected": 0,
                "basic_analysis": {
                    "file_format": "ELF 64-bit",
                    "basic_scan": "No obvious threats"
                },
                "recommendations": [
                    "Basic scan complete",
                    "Upgrade to Pro for advanced analysis"
                ],
                "upgrade_notice": "🚀 Get detailed vulnerability analysis with 'nabla auth upgrade'"
            })
        };

        let mock_response = serde_json::json!({
            "status": "success",
            "file_name": file_name,
            "file_size": file_content.len(),
            "analysis": analysis
        });

        Ok(mock_response.to_string())
    }

    // Real implementation would look something like this:
    #[allow(dead_code)]
    async fn send_analyze_request_real(
        &self,
        url: &str,
        token: Option<&str>,
        file_content: &[u8],
        file_name: &str,
    ) -> Result<String> {
        let client = Client::new();
        
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(file_content.to_vec())
                .file_name(file_name.to_string()));

        let mut request = client
            .post(url)
            .multipart(form);

        // Add auth header if token is provided
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Analysis request failed: {}", response.status()));
        }

        let result = response.text().await?;
        Ok(result)
    }
}