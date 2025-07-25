// src/routes/mod.rs
pub mod binary;
pub mod debug;

pub use binary::{
    upload_and_analyze_binary, diff_binaries, check_cve, health_check, chat_with_binary
};
pub use debug::debug_multipart;