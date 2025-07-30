use anyhow::Result;
use clap::Subcommand;
use reqwest::{Client, multipart};
use serde_json::json;
use sha2::{Digest, Sha256};

mod auth;
mod config;
mod jwt_store;

pub use auth::{AuthArgs, AuthCommands};
pub use config::{ConfigCommands, ConfigStore};
pub use jwt_store::*;
use crate::ssrf_protection::SSRFValidator;

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
        message: String,
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
            Commands::Chat { message } => self.handle_chat_command(&message).await,
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
        }
    }

    fn print_ascii_intro(&self) {
        println!(r#"
    ███╗   ██╗ █████╗ ██████╗ ██╗      █████╗ 
    ████╗  ██║██╔══██╗██╔══██╗██║     ██╔══██╗
    ██╔██╗ ██║███████║██████╔╝██║     ███████║
    ██║╚██╗██║██╔══██║██╔══██╗██║     ██╔══██║
    ██║ ╚████║██║  ██║██████╔╝███████╗██║  ██║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
                                              
    🔒 Binary Analysis & Security Platform
        "#);
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
        let file_path = if file_path.starts_with('@') {
            &file_path[1..]
        } else {
            file_path
        };

        println!("🔍 Analyzing binary: {}", file_path);

        if !std::path::Path::new(file_path).exists() {
            return Err(anyhow::anyhow!("File not found: {}", file_path));
        }

        let jwt_data = self.jwt_store.load_jwt().ok().flatten();
        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/analyze", base_url);

        let file_content = std::fs::read(file_path)?;
        let file_name = std::path::Path::new(file_path)
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

        println!("🔐 Attesting binary: {}", file_path);

        if !std::path::Path::new(file_path).exists() {
            return Err(anyhow::anyhow!("File not found: {}", file_path));
        }
        if !std::path::Path::new(&signing_key).exists() {
            return Err(anyhow::anyhow!("Signing key file not found: {}", signing_key));
        }

        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/attest", base_url);

        let file_content = std::fs::read(file_path)?;
        let file_name = std::path::Path::new(file_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let signing_key_content = std::fs::read(&signing_key)?;

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
        println!("Results: {}", serde_json::to_string_pretty(&json!({
            "analysis": result,
            "attestation": attestation
        }))?);

        Ok(())
    }

    async fn handle_check_cves_command(&mut self, file_path: &str) -> Result<()> {
        let jwt_data = self.jwt_store.load_jwt().ok().flatten();
        println!("🔍 Checking CVEs for: {}", file_path);

        if !std::path::Path::new(file_path).exists() {
            return Err(anyhow::anyhow!("File not found: {}", file_path));
        }

        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/check-cves", base_url);

        let file_content = std::fs::read(file_path)?;
        let file_name = std::path::Path::new(file_path)
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
        let jwt_data = self.jwt_store.load_jwt().ok().flatten();
        println!("🔍 Comparing binaries: {} vs {}", file1, file2);

        if !std::path::Path::new(file1).exists() {
            return Err(anyhow::anyhow!("File not found: {}", file1));
        }
        if !std::path::Path::new(file2).exists() {
            return Err(anyhow::anyhow!("File not found: {}", file2));
        }

        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/diff", base_url);

        let file1_content = std::fs::read(file1)?;
        let file2_content = std::fs::read(file2)?;
        let file1_name = std::path::Path::new(file1)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let file2_name = std::path::Path::new(file2)
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

    async fn handle_chat_command(&mut self, message: &str) -> Result<()> {
        let jwt_data = match self.jwt_store.load_jwt()? {
            Some(data) => data,
            None => {
                println!("❌ Authentication required for chat functionality.");
                println!();
                self.show_upgrade_message();
                return Ok(());
            }
        };

        if !jwt_data.features.chat_enabled {
            println!("❌ Chat feature not available in your current plan.");
            println!();
            self.show_upgrade_message();
            return Ok(());
        }

        println!("💬 Chat: {}", message);

        let base_url = self.config_store.get_base_url()?;
        let url = format!("{}/binary/chat", base_url);

        let ssrf_validator = SSRFValidator::new();
        let validated_url = ssrf_validator.validate_url(&url)?;

        let response = self
            .http_client
            .post(validated_url.to_string())
            .bearer_auth(&jwt_data.token)
            .json(&json!({ "message": message }))
            .send()
            .await?;
        let result = response.json::<serde_json::Value>().await?;

        println!("✅ Chat response received!");
        println!("Response: {}", serde_json::to_string_pretty(&result)?);

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
        println!("  POST /binary/chat      - AI chat (Premium)");
        println!();
        println!("💡 Use Ctrl+C to stop the server");
        println!();

        crate::server::run_server(port).await
    }
}