use clap::Parser;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Simple utility to generate HMAC signatures
#[derive(Parser, Debug)]
#[command(name = "generate_hmac")]
#[command(about = "Generate HMAC signatures")]
#[command(version = VERSION)]
struct Args {
    /// Message to generate HMAC for
    #[arg(long)]
    message: String,
    
    /// Number of bytes for the key (default 32 bytes, only used when no message provided)
    #[arg(short, long, default_value_t = 32)]
    bytes: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Generate HMAC signature for the message
    let key_b64 = std::env::var("LICENSE_SIGNING_KEY")
        .map_err(|_| anyhow::anyhow!("Missing LICENSE_SIGNING_KEY env variable"))?;
    
    let key_bytes = general_purpose::URL_SAFE_NO_PAD.decode(key_b64.trim())?;
    
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)?;
    mac.update(args.message.as_bytes());
    let result = mac.finalize();
    
    // Output the HMAC signature in base64url format
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(result.into_bytes());
    println!("{encoded}");

    Ok(())
}
