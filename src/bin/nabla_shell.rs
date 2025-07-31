use anyhow::Result;
use clap::Parser;
use nabla_cli::cli::{Commands, NablaCli};

#[derive(Parser)]
#[command(name = "nabla")]
#[command(about = "Nabla Binary Analysis CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut nabla_cli = NablaCli::new()?;

    match cli.command {
        Some(command) => nabla_cli.handle_command(command).await,
        None => nabla_cli.show_intro_and_help().await,
    }
}
