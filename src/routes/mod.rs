// src/routes/mod.rs
pub mod binary;
pub mod debug;

pub use binary::{check_cve, diff_binaries, health_check, upload_and_analyze_binary};
pub use debug::debug_multipart;
