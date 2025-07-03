use anyhow::Result;
use async_openai::types::{CreateChatCompletionRequestArgs, ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestUserMessageArgs, ChatCompletionRequestMessage};
use async_openai::Client;
use serde_json::Value as JsonValue;
use crate::models::PackageAnalysis;
use std::env;

/// Enriches the given PackageAnalysis with LLM-generated descriptions and examples.
///
/// This function is best-effort; if the OpenAI request fails it returns Ok(())
/// and leaves the analysis untouched.
pub async fn enrich_analysis(analysis: &mut PackageAnalysis) -> Result<()> {
    tracing::debug!(
        "Starting LLM enrichment for {}:{}",
        analysis.package_name,
        analysis.version
    );

    // Quick check so we log loudly if the key is missing – helps with ops/debugging.
    if env::var("OPENAI_API_KEY").is_err() {
        tracing::warn!("OPENAI_API_KEY is not set – LLM enrichment will fail");
    }

    // Build a condensed source prompt – here we just serialize the key fields.
    // In a production system you would include doc-comments and example code.
    let system_prompt = "You are a Rust crate documentation assistant.";

    let user_prompt = format!(
        "Generate a JSON object with the following optional keys:\n\n\
        1. key_modules_descriptions: array of {{name, description, examples}}.\n\
        2. important_structs_explained: array of {{name, summary}}.\n\
        3. notable_functions_explained: array of {{name, summary}}.\n\
        4. traits_explained: array of {{name, summary}}.\n\
        5. api_usage_examples: array of {{snippet, explanation}}.\n\
        Base your answer on the following crate metadata:\n\
        crate_name: {name}\nversion: {version}\nkey_modules: {modules}\nstructs: {structs}\nfunctions: {funcs}\ntraits: {traits}\n",
        name = analysis.package_name,
        version = analysis.version,
        modules = analysis.key_modules,
        structs = analysis.important_structs,
        funcs = analysis.notable_functions,
        traits = analysis.traits,
    );

    let client = Client::new();
    let system_msg = ChatCompletionRequestMessage::System(
        ChatCompletionRequestSystemMessageArgs::default()
            .content(system_prompt)
            .build()?
    );

    let user_msg = ChatCompletionRequestMessage::User(
        ChatCompletionRequestUserMessageArgs::default()
            .content(user_prompt)
            .build()?
    );

    let messages = vec![system_msg, user_msg];

    let req = CreateChatCompletionRequestArgs::default()
        .model("gpt-4o-mini")
        .max_tokens(800u16)
        .messages(messages)
        .build()?;

    let resp = match client.chat().create(req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("OpenAI enrichment failed: {}", e);
            return Ok(());
        }
    };

    let content = resp.choices[0]
        .message
        .content
        .clone()
        .unwrap_or_default();

    tracing::debug!("Raw LLM response: {}", content);

    // Try to parse JSON – be resilient to markdown fences or extra prose.
    let parsed_json_opt: Option<JsonValue> = match serde_json::from_str::<JsonValue>(&content) {
        Ok(v) => Some(v),
        Err(_) => {
            // Attempt to extract the first JSON object within the text.
            if let (Some(start), Some(end)) = (content.find('{'), content.rfind('}')) {
                let slice = &content[start..=end];
                serde_json::from_str::<JsonValue>(slice).ok()
            } else {
                None
            }
        }
    };

    if let Some(parsed_json) = parsed_json_opt {
        if let Some(arr) = parsed_json.get("key_modules_descriptions") {
            analysis.key_modules = arr.clone();
        }
        if let Some(arr) = parsed_json.get("important_structs_explained") {
            analysis.important_structs = arr.clone();
        }
        if let Some(arr) = parsed_json.get("notable_functions_explained") {
            analysis.notable_functions = arr.clone();
        }
        if let Some(arr) = parsed_json.get("traits_explained") {
            analysis.traits = arr.clone();
        }
        if let Some(arr) = parsed_json.get("api_usage_examples") {
            analysis.api_usage_examples = arr.clone();
        }
        // We intentionally omit any llm_text enrichment – the JSON fields above are sufficient.
    } else {
        // JSON failed to parse; we no longer record raw text.
    }

    tracing::debug!(
        "Finished LLM enrichment for {}:{}",
        analysis.package_name,
        analysis.version
    );

    Ok(())
} 