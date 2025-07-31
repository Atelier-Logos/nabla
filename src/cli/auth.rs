use crate::cli::{JwtData, NablaCli};
use anyhow::Result;

#[derive(clap::Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: Option<AuthCommands>,

    /// Set JWT token for authentication
    #[arg(long = "set-jwt")]
    pub set_jwt: Option<String>,
}

#[derive(clap::Subcommand)]
pub enum AuthCommands {
    Upgrade,
    Status,
}

impl NablaCli {
    pub fn handle_auth_args(&mut self, args: AuthArgs) -> Result<()> {
        // Handle --set-jwt flag first
        if let Some(jwt_token) = args.set_jwt {
            return self.handle_set_jwt(jwt_token);
        }

        // Handle subcommands
        match args.command {
            Some(AuthCommands::Upgrade) => self.handle_auth_upgrade(),
            Some(AuthCommands::Status) => self.handle_auth_status(),
            None => {
                // If no subcommand provided, default to status
                self.handle_auth_status()
            }
        }
    }

    fn handle_set_jwt(&mut self, jwt_token: String) -> Result<()> {
        // Verify JWT against your signing key before storing
        match self.jwt_store.verify_and_store_jwt(&jwt_token) {
            Ok(jwt_data) => {
                println!("✅ JWT token verified and set successfully!");
                println!("User ID: {}", jwt_data.sub);
                println!("Deployment ID: {}", jwt_data.deployment_id);

                // Show available features based on JWT claims
                println!("🎯 Enabled Features:");
                if jwt_data.features.chat_enabled {
                    println!("  • Chat (Premium)");
                }
                if jwt_data.features.api_access {
                    println!("  • API Access");
                }
                if jwt_data.features.sbom_generation {
                    println!("  • SBOM Generation");
                }
                if jwt_data.features.vulnerability_scanning {
                    println!("  • Vulnerability Scanning");
                }
                if jwt_data.features.custom_models {
                    println!("  • Custom Models");
                }

                self.show_portal_link(&jwt_data)?;
            }
            Err(e) => {
                println!("❌ JWT verification failed: {}", e);
                println!("💡 Please ensure you have a valid JWT token from your account manager.");
                println!("🔐 The token must be signed with the authorized key.");
            }
        }
        Ok(())
    }

    fn handle_auth_upgrade(&mut self) -> Result<()> {
        // Check if already authenticated
        if let Some(jwt_data) = self.jwt_store.load_jwt()? {
            println!("✅ You are already authenticated!");
            self.show_portal_link(&jwt_data)?;
            return Ok(());
        }

        // Show upgrade message and open scheduling link
        println!("🚀 Ready to upgrade to Nabla Pro?");
        println!();
        println!("Our security experts will help you:");
        println!("  • Choose the right plan for your needs");
        println!("  • Set up enterprise features like FIPS compliance");
        println!("  • Configure integrations and deployment options");
        println!("  • Provide dedicated support and training");
        println!();

        let scheduling_url = "https://cal.com/team/atelier-logos/platform-intro"; // Replace with your actual Calendly link

        #[cfg(feature = "cloud")]
        {
            if let Err(e) = webbrowser::open(scheduling_url) {
                println!("❌ Could not open browser automatically: {}", e);
                println!("Please visit: {}", scheduling_url);
            } else {
                println!("🌐 Opening scheduling page in your browser...");
                println!("📅 Schedule your demo at: {}", scheduling_url);
            }
        }

        #[cfg(not(feature = "cloud"))]
        {
            println!("📅 Schedule your demo at: {}", scheduling_url);
            println!("💡 Copy and paste this link into your browser to get started.");
        }

        Ok(())
    }

    fn handle_auth_status(&self) -> Result<()> {
        match self.jwt_store.load_jwt()? {
            Some(jwt_data) => {
                println!("✅ Authenticated!");
                println!("User ID: {}", jwt_data.sub);
                println!("Deployment ID: {}", jwt_data.deployment_id);

                // Show available features based on JWT claims
                println!("🎯 Enabled Features:");
                if jwt_data.features.chat_enabled {
                    println!("  • Chat (Premium)");
                }
                if jwt_data.features.api_access {
                    println!("  • API Access");
                }
                if jwt_data.features.sbom_generation {
                    println!("  • SBOM Generation");
                }
                if jwt_data.features.vulnerability_scanning {
                    println!("  • Vulnerability Scanning");
                }
                if jwt_data.features.signed_attestation {
                    println!("  • Signed Attestation (Premium)");
                }
                if jwt_data.features.custom_models {
                    println!("  • Custom Models");
                }

                self.show_portal_link(&jwt_data)?;
            }
            None => {
                println!("❌ Not authenticated");
                println!();
                println!("To get started with Nabla Pro:");
                println!("  • Run 'nabla upgrade' to schedule a demo");
                println!("  • Or visit: https://cal.com/team/atelier-logos/platform-intro");
                println!();
                println!("After our call, you'll receive a token:");
                println!("  nabla auth --set-jwt <YOUR_TOKEN>");
            }
        }
        Ok(())
    }

    pub fn show_portal_link(&self, jwt_data: &JwtData) -> Result<()> {
        let base_url = self.config_store.get_base_url()?;
        self.show_auth_details(jwt_data, &base_url)
    }

    fn show_auth_details(&self, jwt_data: &JwtData, _base_url: &str) -> Result<()> {
        println!();
        println!("🔑 Token: {}", jwt_data.token);
        println!();
        println!("💡 You can also use the CLI to analyze binaries:");
        println!("  nabla analyze /path/to/binary");

        Ok(())
    }
}
