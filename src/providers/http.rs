// src/providers/http.rs
use reqwest::Client;
use serde_json::json;
use async_trait::async_trait;
use super::{InferenceProvider, GenerationOptions, GenerationResponse, InferenceError};

#[derive(Clone)]
pub struct HTTPProvider {
    client: Client,
    inference_url: String,
    api_key: Option<String>,
    provider_token: Option<String>,
}

impl HTTPProvider {
    pub fn new(inference_url: String, api_key: Option<String>, provider_token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            inference_url,
            api_key,
            provider_token,
        }
    }
}

#[async_trait]
impl InferenceProvider for HTTPProvider {
    async fn generate(&self, prompt: &str, options: &GenerationOptions) -> Result<GenerationResponse, InferenceError> {
        // Check if this is a Hugging Face repo request or has a model path (llama.cpp server)
        if options.hf_repo.is_some() || options.model_path.is_some() {
            // Use llama.cpp server's completion endpoint
            let mut request_json = json!({
                "prompt": prompt,
                "n_predict": options.max_tokens,
                "temperature": options.temperature,
                "top_p": options.top_p,
                "stop": options.stop_sequences,
            });
            
            // Add hf_repo if provided
            if let Some(hf_repo) = &options.hf_repo {
                request_json = json!({
                    "prompt": prompt,
                    "n_predict": options.max_tokens,
                    "temperature": options.temperature,
                    "top_p": options.top_p,
                    "stop": options.stop_sequences,
                    "hf_repo": hf_repo,
                });
            }
            
            let mut request = self.client
                .post(&format!("{}/completion", self.inference_url))
                .json(&request_json);
                
            // Add authentication headers
            if let Some(key) = &self.api_key {
                request = request.header("Authorization", format!("Bearer {}", key));
            } else if let Some(token) = &self.provider_token {
                request = request.header("Authorization", format!("Bearer {}", token));
            }
            
            let response = request.send().await
                .map_err(|e| InferenceError::NetworkError(e.to_string()))?;
                
            if !response.status().is_success() {
                return Err(InferenceError::ServerError(format!(
                    "Server returned status: {}", response.status()
                )));
            }
            
            let result: serde_json::Value = response.json().await
                .map_err(|e| InferenceError::ServerError(format!("Failed to parse response: {}", e)))?;
            
            // Parse llama.cpp server response format
            let content = result["content"].as_str()
                .ok_or_else(|| InferenceError::ServerError("Missing content in response".to_string()))?;
            let tokens_used = result["tokens_predicted"].as_u64().unwrap_or(0) as usize;
            let stop_reason = result["stop_type"].as_str().unwrap_or("").to_string();
            
            Ok(GenerationResponse {
                text: content.to_string(),
                tokens_used,
                finish_reason: stop_reason,
            })
        } else {
            // Fallback to OpenAI-compatible endpoint
            let mut request = self.client
                .post(&format!("{}/v1/chat/completions", self.inference_url))
                .json(&json!({
                    "model": options.model.as_deref().unwrap_or("gpt-3.5-turbo"),
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": options.max_tokens,
                    "temperature": options.temperature,
                    "top_p": options.top_p,
                }));
                
            // Add authentication headers
            if let Some(key) = &self.api_key {
                request = request.header("Authorization", format!("Bearer {}", key));
            } else if let Some(token) = &self.provider_token {
                request = request.header("Authorization", format!("Bearer {}", token));
            }
            
            let response = request.send().await
                .map_err(|e| InferenceError::NetworkError(e.to_string()))?;
                
            if !response.status().is_success() {
                return Err(InferenceError::ServerError(format!(
                    "Server returned status: {}", response.status()
                )));
            }
            
            let result: serde_json::Value = response.json().await
                .map_err(|e| InferenceError::ServerError(format!("Failed to parse response: {}", e)))?;
            
            // Parse OpenAI-compatible response format
            let content = result["choices"][0]["message"]["content"].as_str()
                .ok_or_else(|| InferenceError::ServerError("Missing content in response".to_string()))?;
            let tokens_used = result["usage"]["total_tokens"].as_u64().unwrap_or(0) as usize;
            let finish_reason = result["choices"][0]["finish_reason"].as_str().unwrap_or("").to_string();
            
            Ok(GenerationResponse {
                text: content.to_string(),
                tokens_used,
                finish_reason,
            })
        }
    }

    async fn is_available(&self) -> bool {
        // Try to ping the server
        match self.client.get(&format!("{}/props", self.inference_url)).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }
}