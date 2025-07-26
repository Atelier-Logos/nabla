// src/providers/mod.rs
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod http;
pub use http::HTTPProvider;

#[async_trait]
pub trait InferenceProvider: Send + Sync {
    async fn generate(&self, prompt: &str, options: &GenerationOptions) -> Result<GenerationResponse, InferenceError>;
    #[allow(dead_code)]
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, InferenceError> {
        // Default implementation - not all providers need to implement this
        Err(InferenceError::ServerError("Embedding not supported".to_string()))
    }
    #[allow(dead_code)]
    async fn is_available(&self) -> bool; // Make this async
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenerationOptions {
    pub max_tokens: usize,
    pub temperature: f32,
    pub top_p: f32,
    pub stop_sequences: Vec<String>,
    pub model_path: Option<String>, // For local GGUF files
    pub hf_repo: Option<String>,    // For remote HF repos
    pub model: Option<String>,      // For OpenAI-compatible APIs (e.g., Together, OpenAI)
}

impl Default for GenerationOptions {
    fn default() -> Self {
        Self {
            max_tokens: 512,
            temperature: 0.7,
            top_p: 0.9,
            stop_sequences: vec![],
            model_path: None,
            hf_repo: None,
            model: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerationResponse {
    pub text: String,
    pub tokens_used: usize,
    pub finish_reason: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    #[allow(dead_code)]
    #[error("No available inference provider")]
    NoAvailableProvider,
    #[error("Server error: {0}")]
    ServerError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}