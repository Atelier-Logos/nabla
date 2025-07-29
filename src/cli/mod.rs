use anyhow::Result;
use clap::Subcommand;

mod auth;
mod config;
mod analyze;
mod jwt_store;

pub use auth::{AuthArgs, AuthCommands};
pub use config::{ConfigCommands, ConfigStore};
pub use jwt_store::*;

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
    Analyze {
        file: String,
    },
    // Stubs for other endpoints
    Binary {
        file: String,
    },
    Diff {
        file1: String,
        file2: String,
    },
    Chat {
        message: String,
    },
}


pub struct NablaCli {
    jwt_store: JwtStore,
    config_store: ConfigStore,
}

impl NablaCli {
    pub fn new() -> Result<Self> {
        Ok(Self {
            jwt_store: JwtStore::new()?,
            config_store: ConfigStore::new()?,
        })
    }

    pub fn show_intro_and_help(&self) -> Result<()> {
        self.print_ascii_intro();
        self.print_help();
        Ok(())
    }

    pub fn handle_command(&mut self, command: Commands) -> Result<()> {
        match command {
            Commands::Auth { args } => self.handle_auth_args(args),
            Commands::Config { command } => self.handle_config_command(command),
            Commands::Analyze { file } => self.handle_analyze_command(&file),
            Commands::Binary { file } => {
                println!("🔧 Binary analysis for {} - Not yet implemented", file);
                Ok(())
            }
            Commands::Diff { file1, file2 } => {
                println!("🔍 Diff analysis between {} and {} - Not yet implemented", file1, file2);
                Ok(())
            }
            Commands::Chat { message } => {
                println!("💬 Chat: {} - Not yet implemented", message);
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
        println!("  nabla config list           - List all configuration");
        println!();
        println!("🔍 Analysis:");
        println!("  nabla analyze <file>  - Analyze a binary file");
        println!();
        println!("🚀 Coming Soon:");
        println!("  nabla binary <file>   - Binary analysis");
        println!("  nabla diff <f1> <f2>  - Compare two binaries");
        println!("  nabla chat <message>  - Chat about analysis");
        println!();
        println!("💡 Tip: Run 'nabla auth upgrade' to unlock premium features!");
    }
}