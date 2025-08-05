use anyhow::Result;
use clap::Subcommand;
use reqwest::{Client, multipart};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

mod auth;
mod config;
mod jwt_store;

use crate::ssrf_protection::SSRFValidator;
pub use auth::AuthArgs;
pub use config::{ConfigCommands, ConfigStore, LLMProvider, LLMProvidersConfig};
pub use jwt_store::*;

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB limit

fn validate_file_path(file_path: &str) -> Result<PathBuf> {
    // Remove any @ prefix if present
    let clean_path = if file_path.starts_with('@') {
        &file_path[1..]
    } else {
        file_path
    };

    let path = Path::new(clean_path);

    // Check if file exists
    if !path.exists() {
        return Err(anyhow::anyhow!("File not found: {}", clean_path));
    }

    // Get canonical path to resolve any .. or . components
    let canonical_path = path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("Invalid file path '{}': {}", clean_path, e))?;

    // Get current working directory
    let current_dir = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("Cannot determine current directory: {}", e))?;

    // Ensure the canonical path is within or below the current working directory
    if !canonical_path.starts_with(&current_dir) {
        return Err(anyhow::anyhow!(
            "Access denied: file '{}' is outside the current working directory",
            clean_path
        ));
    }

    // Check file size
    let metadata = std::fs::metadata(&canonical_path)
        .map_err(|e| anyhow::anyhow!("Cannot read file metadata: {}", e))?;

    if metadata.len() > MAX_FILE_SIZE {
        return Err(anyhow::anyhow!(
            "File too large: {} bytes (max: {} bytes)",
            metadata.len(),
            MAX_FILE_SIZE
        ));
    }

    // Ensure it's a regular file, not a symlink or directory
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "Path must be a regular file: {}",
            clean_path
        ));
    }

    Ok(canonical_path)
}

#[derive(Subcommand)]
pub enum Commands {
    Auth {
        #[command(flatten)]
        args: AuthArgs,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    Binary {
        #[command(subcommand)]
        command: BinaryCommands,
    },
    Diff {
        file1: String,
        file2: String,
    },
    Chat {
        file: String,
        message: String,
        #[arg(long)]
        provider: Option<String>, // Optional provider name, uses default if not specified
    },
    Upgrade,
    Server {
        #[arg(long, default_value = "8080")]
        port: u16,
    },
}

#[derive(Subcommand)]
pub enum BinaryCommands {
    Analyze {
        file: String,
    },
    Attest {
        file: String,
        #[arg(long)]
        signing_key: String,
    },
    CheckCves {
        file: String,
    },
}

pub struct NablaCli {
    jwt_store: JwtStore,
    config_store: ConfigStore,
    http_client: Client,
}

impl NablaCli {
    pub fn new() -> Result<Self> {
        Ok(Self {
            jwt_store: JwtStore::new()?,
            config_store: ConfigStore::new()?,
            http_client: Client::new(),
        })
    }

    pub async fn show_intro_and_help(&self) -> Result<()> {
        self.print_ascii_intro();
        self.print_help();
        Ok(())
    }

    pub async fn handle_command(&mut self, command: Commands) -> Result<()> {
        match command {
            Commands::Auth { args } => self.handle_auth_args(args),
            Commands::Config { command } => self.handle_config_command(command),
            Commands::Binary { command } => self.handle_binary_command(command).await,
            Commands::Diff { file1, file2 } => self.handle_diff_command(&file1, &file2).await,
            Commands::Chat {
                file,
                message,
                provider,
            } => {
                self.handle_chat_command(&file, &message, provider.as_deref())
                    .await
            }
            Commands::Upgrade => self.handle_upgrade_command(),
            Commands::Server { port } => self.handle_server_command(port).await,
        }
    }

    fn handle_config_command(&mut self, command: ConfigCommands) -> Result<()> {
        match command {
            ConfigCommands::Get { key } => {
                let value = self.config_store.get_setting(&key)?;
                match value {
                    Some(val) => println!("{}: {}", key, val),
                    None => println!("No value set for key: {}", key),
                }
                Ok(())
            }
            ConfigCommands::Set { key, value } => {
                self.config_store.set_setting(&key, &value)?;
                println!("Set {} = {}", key, value);
                Ok(())
            }
            ConfigCommands::SetBaseUrl { url } => self.config_store.set_base_url(&url),
            ConfigCommands::List => {
                let settings = self.config_store.list_settings()?;
                if settings.is_empty() {
                    println!("No configuration settings found.");
                } else {
                    println!("Configuration settings:");
                    for (key, value) in settings {
                        println!("  {}: {}", key, value);
                    }
                }
                Ok(())
            }
            ConfigCommands::AddProvider {
                name,
                provider_type,
                api_key,
                base_url,
                model,
                default,
            } => {
                let mut providers_config = LLMProvidersConfig::new()?;
                let provider = LLMProvider {
                    name: name.clone(),
                    provider_type,
                    api_key,
                    base_url,
                    model,
                    default,
                };
                providers_config.add_provider(provider)?;
                println!("✅ Added LLM provider: {}", name);
                Ok(())
            }
            ConfigCommands::RemoveProvider { name } => {
                let mut providers_config = LLMProvidersConfig::new()?;
                providers_config.remove_provider(&name)?;
                println!("✅ Removed LLM provider: {}", name);
                Ok(())
            }
            ConfigCommands::ListProviders => {
                let providers_config = LLMProvidersConfig::new()?;
                let providers = providers_config.list_providers();
                if providers.is_empty() {
                    println!("No LLM providers configured.");
                    println!();
                    println!("💡 Add a provider with:");
                    println!(
                        "  nabla config add-provider <name> --provider-type openai --base-url https://api.openai.com --api-key <your-key>"
                    );
                } else {
                    println!("Configured LLM providers:");
                    for provider in providers {
                        let default_marker = if provider.default { " (default)" } else { "" };
                        let api_key_status = if provider.api_key.is_some() {
                            "✅"
                        } else {
                            "❌"
                        };
                        println!(
                            "  {} {}{} - {} - Key: {}",
                            provider.name,
                            provider.provider_type,
                            default_marker,
                            provider.base_url,
                            api_key_status
                        );
                    }
                }
                Ok(())
            }
            ConfigCommands::SetDefaultProvider { name } => {
                let mut providers_config = LLMProvidersConfig::new()?;
                providers_config.set_default_provider(&name)?;
                println!("✅ Set default LLM provider: {}", name);
                Ok(())
            }
        }
    }

    fn print_ascii_intro(&self) {
        println!(
            r#"
    ███╗   ██╗ █████╗ ██████╗ ██╗      █████╗ 
    ████╗  ██║██╔══██╗██╔══██╗██║     ██╔══██╗
    ██╔██╗ ██║███████║██████╔╝██║     ███████║
    ██║╚██╗██║██╔══██║██╔══██╗██║     ██╔══██║
    ██║ ╚████║██║  ██║██████╔╝███████╗██║  ██║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
                                              
    🔒 Binary Analysis & Security Platform
        "#
        );
    }

    fn print_help(&self) {
        println!("Available Commands:");
        println!();
        println!("🔐 Authentication:");
        println!("  nabla auth upgrade      - Upgrade your plan");
        println!("  nabla auth status       - Check authentication status");
        println!("  nabla auth --set-jwt <token> - Set JWT token for authentication");
        println!();
        println!("⚙️  Configuration:");
        println!("  nabla config get <key>      - Get configuration value");
        println!("  nabla config set <key> <val> - Set configuration value");
        println!("  nabla config set-base-url <url> - Set base URL for API requests");
        println!("  nabla config list           - List all configuration");
        println!();
        println!("🔍 Binary Analysis:");
        println!("  nabla binary analyze <file>  - Analyze a binary file");
        println!("  nabla binary attest --signing-key <key> <file> - Create signed attestation");
        println!("  nabla binary check-cves <file> - Check for CVEs");
        println!();
        println!("🔍 Comparison:");
        println!("  nabla diff <file1> <file2>   - Compare two binaries");
        println!();
        println!("💬 Chat (Premium Feature):");
        println!("  nabla chat <message>         - Chat about analysis");
        println!();
        println!("🚀 Upgrade:");
        println!("  nabla upgrade               - Upgrade to AWS Marketplace plan");
        println!();
        println!("🖥️  Server:");
        println!("  nabla server --port <port>  - Start HTTP server (default: 8080)");
        println!();
        println!("💡 Tip: Run 'nabla upgrade' to unlock premium features!");
    }

    async fn handle_binary_command(&mut self, command: BinaryCommands) -> Result<()> {
        match command {
            BinaryCommands::Analyze { file } => self.handle_analyze_command(&file).await,
            BinaryCommands::Attest { file, signing_key } => {
                self.handle_attest_command(&file, signing_key).await
            }
            BinaryCommands::CheckCves { file } => self.handle_check_cves_command(&file).await,
        }
    }

    async fn handle_analyze_command(&mut self, file_path: &str) -> Result<()> {
        let validated_path = validate_file_path(file_path)?;

        println!("🔍 Analyzing binary: {}", validated_path.display());

        let jwt_data = self.jwt_store.load_jwt().ok().flatten();
        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/analyze", base_url);

        let file_content = std::fs::read(&validated_path)?;
        let file_name = validated_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        println!("🔄 Uploading to analysis endpoint...");

        let ssrf_validator = SSRFValidator::new();
        let validated_url = ssrf_validator.validate_url(&url)?;

        let part = multipart::Part::bytes(file_content).file_name(file_name);
        let form = multipart::Form::new().part("file", part);

        let mut request = self.http_client.post(validated_url.to_string());
        if let Some(jwt) = jwt_data.as_ref() {
            request = request.bearer_auth(&jwt.token);
        }

        let response = request.multipart(form).send().await?;
        let result = response.json::<serde_json::Value>().await?;

        println!("✅ Analysis complete!");
        println!("Results: {}", serde_json::to_string_pretty(&result)?);

        Ok(())
    }

    async fn handle_attest_command(&mut self, file_path: &str, signing_key: String) -> Result<()> {
        let jwt_data = self.jwt_store.load_jwt()?
            .ok_or_else(|| anyhow::anyhow!("Authentication required for binary attestation. Run 'nabla auth --set-jwt <token>' or 'nabla upgrade'"))?;

        let validated_file_path = validate_file_path(file_path)?;
        let validated_key_path = validate_file_path(&signing_key)?;

        println!("🔐 Attesting binary: {}", validated_file_path.display());

        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/attest", base_url);

        let file_content = std::fs::read(&validated_file_path)?;
        let file_name = validated_file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let signing_key_content = std::fs::read(&validated_key_path)?;

        println!("🔄 Uploading to attestation endpoint...");

        let ssrf_validator = SSRFValidator::new();
        let validated_url = ssrf_validator.validate_url(&url)?;

        let file_part = multipart::Part::bytes(file_content.clone()).file_name(file_name.clone());
        let key_part = multipart::Part::bytes(signing_key_content).file_name("key.pem");
        let form = multipart::Form::new()
            .part("file", file_part)
            .part("signing_key", key_part);

        let response = self
            .http_client
            .post(validated_url.to_string())
            .bearer_auth(&jwt_data.token)
            .multipart(form)
            .send()
            .await?;
        let result = response.json::<serde_json::Value>().await?;

        // Mock attestation using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&file_content);
        let hash = hasher.finalize();
        let attestation = json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": file_name,
                "digest": {
                    "sha256": format!("{:x}", hash)
                }
            }],
            "predicateType": "https://nabla.sh/attestation/v0.1",
            "predicate": {
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "analysis": {
                    "format": "ELF",
                    "architecture": "x86_64",
                    "security_score": 85
                }
            }
        });

        println!("✅ Attestation complete!");
        println!(
            "Results: {}",
            serde_json::to_string_pretty(&json!({
                "analysis": result,
                "attestation": attestation
            }))?
        );

        Ok(())
    }

    async fn handle_check_cves_command(&mut self, file_path: &str) -> Result<()> {
        let validated_path = validate_file_path(file_path)?;
        let jwt_data = self.jwt_store.load_jwt().ok().flatten();

        println!("🔍 Checking CVEs for: {}", validated_path.display());

        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/check-cves", base_url);

        let file_content = std::fs::read(&validated_path)?;
        let file_name = validated_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        println!("🔄 Uploading to CVE check endpoint...");

        let ssrf_validator = SSRFValidator::new();
        let validated_url = ssrf_validator.validate_url(&url)?;

        let part = multipart::Part::bytes(file_content).file_name(file_name);
        let form = multipart::Form::new().part("file", part);

        let mut request = self.http_client.post(validated_url.to_string());
        if let Some(jwt) = jwt_data.as_ref() {
            request = request.bearer_auth(&jwt.token);
        }

        let response = request.multipart(form).send().await?;
        let result = response.json::<serde_json::Value>().await?;

        println!("✅ CVE check complete!");
        println!("Results: {}", serde_json::to_string_pretty(&result)?);

        Ok(())
    }

    async fn handle_diff_command(&mut self, file1: &str, file2: &str) -> Result<()> {
        let validated_path1 = validate_file_path(file1)?;
        let validated_path2 = validate_file_path(file2)?;
        let jwt_data = self.jwt_store.load_jwt().ok().flatten();

        println!(
            "🔍 Comparing binaries: {} vs {}",
            validated_path1.display(),
            validated_path2.display()
        );

        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/diff", base_url);

        let file1_content = std::fs::read(&validated_path1)?;
        let file2_content = std::fs::read(&validated_path2)?;
        let file1_name = validated_path1
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let file2_name = validated_path2
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        println!("🔄 Uploading files to diff endpoint...");

        let ssrf_validator = SSRFValidator::new();
        let validated_url = ssrf_validator.validate_url(&url)?;

        let file1_part = multipart::Part::bytes(file1_content).file_name(file1_name);
        let file2_part = multipart::Part::bytes(file2_content).file_name(file2_name);
        let form = multipart::Form::new()
            .part("file1", file1_part)
            .part("file2", file2_part);

        let mut request = self.http_client.post(validated_url.to_string());
        if let Some(jwt) = jwt_data.as_ref() {
            request = request.bearer_auth(&jwt.token);
        }

        let response = request.multipart(form).send().await?;
        let result = response.json::<serde_json::Value>().await?;

        println!("✅ Diff analysis complete!");
        println!("Results: {}", serde_json::to_string_pretty(&result)?);

        Ok(())
    }

    async fn handle_chat_command(
        &mut self,
        file_path: &str,
        message: &str,
        provider_name: Option<&str>,
    ) -> Result<()> {
        // For OSS, we don't require JWT authentication - just check if providers are configured
        let base_url = self.config_store.get_base_url()?;

        // Load LLM provider configuration
        let providers_config = LLMProvidersConfig::new()?;

        let provider = if let Some(name) = provider_name {
            providers_config.get_provider(name)
                .ok_or_else(|| anyhow::anyhow!("Provider '{}' not found. Use 'nabla config list-providers' to see available providers.", name))?
        } else {
            providers_config.get_default_provider()
                .ok_or_else(|| anyhow::anyhow!("No default provider configured. Use 'nabla config add-provider' to add one or specify --provider <name>"))?
        };

        // Validate and read the file
        let validated_path = validate_file_path(file_path)?;
        let file_name = validated_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        println!("🔍 Analyzing file: {}", file_name);
        println!("💬 Question: {}", message);
        println!(
            "🤖 Using provider: {} ({})",
            provider.name, provider.provider_type
        );

        let url = format!("{}/binary/chat", base_url);
        let ssrf_validator = SSRFValidator::new();
        let validated_url = ssrf_validator.validate_url(&url)?;

        // Create request payload matching the API format
        let mut request_body = json!({
            "file_path": validated_path.to_string_lossy(),
            "question": message,
            "provider": "http", // Always use HTTP provider for configured providers
            "inference_url": provider.base_url,
        });

        // Add API key if available
        if let Some(api_key) = &provider.api_key {
            request_body["provider_token"] = json!(api_key);
        }

        // Add model if specified
        if let Some(model) = &provider.model {
            request_body["model_path"] = json!(model);
        }

        let mut request = self.http_client.post(validated_url.to_string());

        // Only add JWT auth if we have it (for enterprise features)
        if let Some(jwt_data) = self.jwt_store.load_jwt()? {
            request = request.bearer_auth(&jwt_data.token);
        }

        let response = request.json(&request_body).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("Chat request failed: {}", error_text));
        }

        let result = response.json::<serde_json::Value>().await?;

        println!("✅ Analysis complete!");
        if let Some(answer) = result.get("answer") {
            println!(
                "\n📝 Response:\n{}",
                answer.as_str().unwrap_or("No response")
            );
        }
        if let Some(model_used) = result.get("model_used") {
            println!("\n🤖 Model: {}", model_used.as_str().unwrap_or("unknown"));
        }

        Ok(())
    }

    fn handle_upgrade_command(&mut self) -> Result<()> {
        if let Some(_jwt_data) = self.jwt_store.load_jwt()? {
            println!("✅ You are already authenticated!");
            println!();
            println!("💡 You can use the CLI to analyze binaries:");
            println!("  nabla binary analyze /path/to/binary");
            return Ok(());
        }

        self.show_upgrade_message();
        Ok(())
    }

    fn show_upgrade_message(&self) {
        let scheduling_url = "https://cal.com/team/atelier-logos/platform-intro";

        println!("🚀 Ready to upgrade to Nabla Pro?");
        println!();
        println!("Let's discuss the perfect plan for your security needs:");
        println!("  • Binary analysis with AI-powered insights");
        println!("  • Signed attestation and compliance features");
        println!("  • Custom deployment and enterprise integrations");
        println!("  • Dedicated support and training");
        println!();

        #[cfg(feature = "cloud")]
        {
            if let Err(e) = webbrowser::open(scheduling_url) {
                println!("❌ Could not open browser automatically: {}", e);
                println!("Please visit: {}", scheduling_url);
            } else {
                println!("🌐 Opening scheduling page in your browser...");
                println!("📅 Schedule your demo: {}", scheduling_url);
            }
        }

        #[cfg(not(feature = "cloud"))]
        {
            println!("📅 Schedule your demo: {}", scheduling_url);
            println!("💡 Copy and paste this link into your browser to get started.");
        }

        println!();
        println!("After our call, you'll receive a token to get started:");
        println!("  nabla auth --set-jwt <YOUR_TOKEN>");
    }

    async fn handle_server_command(&self, port: u16) -> Result<()> {
        println!("🚀 Starting Nabla server on port {}", port);
        println!("📡 Server will be available at: http://localhost:{}", port);
        println!("🔐 Endpoints:");
        println!("  POST /binary/analyze   - Binary analysis");
        println!("  POST /binary/attest    - Binary attestation (Premium)");
        println!("  POST /binary/check-cves - CVE checking");
        println!("  POST /binary/diff      - Binary comparison");
        println!("  POST /binary/chat      - AI chat");
        println!();
        println!("💡 Use Ctrl+C to stop the server");
        println!();

        crate::server::run_server(port).await
    }
}
