// src/binary/ai_enhanced.rs
use crate::providers::{InferenceProvider, GenerationOptions, GenerationResponse};
use crate::binary::BinaryAnalysis;

pub async fn generate_sbom_from_analysis(
    analysis: &BinaryAnalysis,
    provider: &dyn InferenceProvider,
    options: &GenerationOptions,
) -> Result<serde_json::Value, anyhow::Error> {
    let prompt = format!(
        "Generate a Software Bill of Materials (SBOM) in CycloneDX JSON format for this binary analysis. Return ONLY valid JSON, no other text:\n\n\
         File: {}\n\
         Format: {}\n\
         Architecture: {}\n\
         Linked Libraries: {}\n\
         Embedded Strings: {}\n\
         \nGenerate a complete CycloneDX JSON SBOM with all detected components. The response must be valid JSON starting with {{ and ending with }}.",
        analysis.file_name,
        analysis.format,
        analysis.architecture,
        analysis.linked_libraries.join(", "),
        analysis.embedded_strings.join(", ")
    );
    
    let response = provider.generate(&prompt, options).await
        .map_err(|e| anyhow::anyhow!("Inference failed: {}", e))?;
    
    // Parse the response as SPDX JSON
    serde_json::from_str(&response.text)
        .map_err(|e| anyhow::anyhow!("Failed to parse SBOM: {}", e))
}

pub async fn chat_with_binary(
    analysis: &BinaryAnalysis,
    user_question: &str,
    provider: &dyn InferenceProvider,
    options: &GenerationOptions,
) -> Result<GenerationResponse, anyhow::Error> {
    let context = format!(
        "Binary Analysis Context:\n\
         - File: {}\n\
         - Format: {}\n\
         - Architecture: {}\n\
         - Size: {} bytes\n\
         - Linked Libraries: {}\n\
         - Imports: {}\n\
         - Exports: {}\n\
         - Embedded Strings: {}\n\n\
         User Question: {}\n\n\
         Please provide a helpful answer about this binary based on the analysis data.",
        analysis.file_name,
        analysis.format,
        analysis.architecture,
        analysis.size_bytes,
        analysis.linked_libraries.join(", "),
        analysis.imports.join(", "),
        analysis.exports.join(", "),
        analysis.embedded_strings.join(", "),
        user_question
    );
    
    provider.generate(&context, options).await
        .map_err(|e| anyhow::anyhow!("Inference failed: {}", e))
}