// src/routes/mod.rs
pub mod binary;
pub mod packages;
pub mod debug;

pub use binary::{
    upload_and_analyze_binary, get_binary_analysis, 
    scan_binary_secrets, get_binary_sbom
};
pub use packages::{analyze_package, fetch_package_analysis, health_check};
pub use debug::debug_multipart;