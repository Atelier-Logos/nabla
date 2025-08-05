pub mod behavioral_analysis;
pub mod crypto_analysis;
pub mod control_flow;
pub mod static_analysis;
pub mod supply_chain;

// Re-export main analysis functions for easy access
pub use behavioral_analysis::analyze_behavioral_security;
pub use crypto_analysis::analyze_crypto_security;
pub use static_analysis::analyze_static_security;
pub use control_flow::build_cfg;
pub use supply_chain::analyze_supply_chain_security;

// Re-export main analysis functions for easy access
