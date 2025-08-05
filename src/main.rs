use clap::Parser;
use nabla_cli::cli::{Commands, NablaCli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    #[derive(Parser)]
    #[command(name = "nabla")]
    #[command(about = "Nabla Binary Analysis & Security Platform")]
    struct Cli {
        #[command(subcommand)]
        command: Option<Commands>,
    }

    let cli = Cli::parse();

    // Handle CLI commands
    match cli.command {
        Some(command) => {
            let mut nabla_cli = NablaCli::new()?;
            nabla_cli.handle_command(command).await
        }
        None => {
            // Show help when no command is provided
            let nabla_cli = NablaCli::new()?;
            nabla_cli.show_intro_and_help().await
        }
    }
}
