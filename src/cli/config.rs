use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::fs;
use std::collections::HashMap;
use clap::Subcommand;
use home;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigData {
    pub base_url: Option<String>,
    pub settings: HashMap<String, String>,
}

impl Default for ConfigData {
    fn default() -> Self {
        Self {
            base_url: None,
            settings: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigStore {
    #[serde(default)]
    settings: std::collections::HashMap<String, String>,
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
        
        Err(anyhow!("No base URL configured. Set with 'nabla config set-base-url <url>' or NABLA_BASE_URL env var"))
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
        let home = home::home_dir()
            .ok_or_else(|| anyhow!("Could not determine home directory"))?;
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

    pub fn load_config(&self) -> Result<ConfigData> {
        let config_path = Self::get_config_path()?;
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: ConfigData = serde_json::from_str(&content).unwrap_or_default();
            Ok(config)
        } else {
            Ok(ConfigData::default())
        }
    }
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    Get { key: String },
    Set { key: String, value: String },
    SetBaseUrl { url: String },
    List,
}

