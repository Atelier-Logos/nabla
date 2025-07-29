use anyhow::Result;
use clap::Parser;
use nabla::cli::{NablaCli, Commands};

#[derive(Parser)]
#[command(name = "nabla")]
#[command(about = "Nabla Binary Analysis CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut nabla_cli = NablaCli::new()?;

    match cli.command {
        Some(command) => nabla_cli.handle_command(command),
        None => nabla_cli.show_intro_and_help(),
    }
}