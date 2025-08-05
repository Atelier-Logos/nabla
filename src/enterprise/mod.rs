pub mod attestation;
#[allow(dead_code)]
pub mod secure;
pub mod types;

// Re-export main analysis functions from secure module for easy access
pub use secure::analyze_behavioral_security;
pub use secure::analyze_crypto_security;
pub use secure::analyze_static_security;
pub use secure::analyze_supply_chain_security;
