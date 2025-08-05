use anyhow::{Result, anyhow};
use clap::Subcommand;
use home;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct LLMProvider {
    pub name: String,
    pub provider_type: String, // "openai", "groq", "together", "local"
    pub api_key: Option<String>,
    pub base_url: String,
    pub model: Option<String>,
    pub default: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub struct LLMProvidersConfig {
    pub providers: HashMap<String, LLMProvider>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigStore {
    #[serde(default)]
    settings: HashMap<String, String>,
}

impl ConfigStore {
    pub fn new() -> Result<Self> {
        let config_path = Self::get_config_path()?;
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: ConfigStore = serde_json::from_str(&content)?;
            Ok(config)
        } else {
            Ok(ConfigStore::default())
        }
    }

    pub fn get_base_url(&self) -> Result<String> {
        // Try config setting first, then environment variable, then error
        if let Some(url) = self.get_setting("base_url")? {
            return Ok(url);
        }

        if let Ok(url) = std::env::var("NABLA_BASE_URL") {
            return Ok(url);
        }

        Err(anyhow!(
            "No base URL configured. Set with 'nabla config set-base-url <url>' or NABLA_BASE_URL env var"
        ))
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self.settings.get(key).cloned())
    }

    pub fn set_setting(&mut self, key: &str, value: &str) -> Result<()> {
        self.settings.insert(key.to_string(), value.to_string());
        self.save()
    }

    pub fn set_base_url(&mut self, url: &str) -> Result<()> {
        // Validate URL format
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(anyhow!("Base URL must start with http:// or https://"));
        }
        self.set_setting("base_url", url)?;
        println!("✅ Base URL set to: {}", url);
        Ok(())
    }

    pub fn list_settings(&self) -> Result<Vec<(String, String)>> {
        let mut settings: Vec<(String, String)> = self
            .settings
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        settings.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(settings)
    }

    fn get_config_path() -> Result<std::path::PathBuf> {
        let home = home::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        let config_dir = home.join(".nabla");
        fs::create_dir_all(&config_dir)?;
        Ok(config_dir.join("config.json"))
    }

    fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path()?;
        let content = serde_json::to_string_pretty(&self)?;
        fs::write(&config_path, content)?;
        Ok(())
    }
}

impl LLMProvidersConfig {
    pub fn new() -> Result<Self> {
        let providers_path = Self::get_providers_path()?;
        if providers_path.exists() {
            let content = fs::read_to_string(&providers_path)?;
            let config: LLMProvidersConfig = serde_json::from_str(&content)?;
            Ok(config)
        } else {
            Ok(LLMProvidersConfig::default())
        }
    }

    pub fn add_provider(&mut self, provider: LLMProvider) -> Result<()> {
        // If this is marked as default, unset other defaults
        if provider.default {
            for (_, existing_provider) in self.providers.iter_mut() {
                existing_provider.default = false;
            }
        }

        self.providers.insert(provider.name.clone(), provider);
        self.save()
    }

    pub fn remove_provider(&mut self, name: &str) -> Result<()> {
        self.providers.remove(name);
        self.save()
    }

    pub fn get_provider(&self, name: &str) -> Option<&LLMProvider> {
        self.providers.get(name)
    }

    pub fn get_default_provider(&self) -> Option<&LLMProvider> {
        self.providers.values().find(|p| p.default)
    }

    pub fn list_providers(&self) -> Vec<&LLMProvider> {
        let mut providers: Vec<&LLMProvider> = self.providers.values().collect();
        providers.sort_by(|a, b| a.name.cmp(&b.name));
        providers
    }

    pub fn set_default_provider(&mut self, name: &str) -> Result<()> {
        // Unset all defaults first
        for (_, provider) in self.providers.iter_mut() {
            provider.default = false;
        }

        // Set the new default
        if let Some(provider) = self.providers.get_mut(name) {
            provider.default = true;
            self.save()
        } else {
            Err(anyhow!("Provider '{}' not found", name))
        }
    }

    fn get_providers_path() -> Result<std::path::PathBuf> {
        let home = home::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        let config_dir = home.join(".nabla");
        fs::create_dir_all(&config_dir)?;
        Ok(config_dir.join("llm_providers.json"))
    }

    fn save(&self) -> Result<()> {
        let providers_path = Self::get_providers_path()?;
        let content = serde_json::to_string_pretty(&self)?;
        fs::write(&providers_path, content)?;
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    Get {
        key: String,
    },
    Set {
        key: String,
        value: String,
    },
    SetBaseUrl {
        url: String,
    },
    List,

    // LLM Provider management
    AddProvider {
        name: String,
        #[arg(long)]
        provider_type: String, // openai, groq, together, local
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        default: bool,
    },
    RemoveProvider {
        name: String,
    },
    ListProviders,
    SetDefaultProvider {
        name: String,
    },
}
