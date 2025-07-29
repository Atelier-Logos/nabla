use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use std::fs;
use std::collections::HashMap;
use home::home_dir;
use crate::cli::NablaCli;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigData {
    pub base_url: Option<String>,
    pub settings: HashMap<String, String>,
}

impl Default for ConfigData {
    fn default() -> Self {
        Self {
            base_url: Some("https://nabla.atelierlogos.studio".to_string()),
            settings: HashMap::new(),
        }
    }
}

pub struct ConfigStore {
    store_path: PathBuf,
}

impl ConfigStore {
    pub fn new() -> Result<Self> {
        let home = home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
        let nabla_dir = home.join(".nabla");
        
        if !nabla_dir.exists() {
            fs::create_dir_all(&nabla_dir)?;
        }
        
        Ok(Self {
            store_path: nabla_dir.join("config.json"),
        })
    }

    pub fn load_config(&self) -> Result<ConfigData> {
        if !self.store_path.exists() {
            let default_config = ConfigData::default();
            self.save_config(&default_config)?;
            return Ok(default_config);
        }

        let content = fs::read_to_string(&self.store_path)?;
        let config: ConfigData = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save_config(&self, config: &ConfigData) -> Result<()> {
        let json = serde_json::to_string_pretty(config)?;
        fs::write(&self.store_path, json)?;
        Ok(())
    }

    pub fn get_base_url(&self) -> Result<String> {
        let config = self.load_config()?;
        Ok(config.base_url.unwrap_or_else(|| "https://nabla.atelierlogos.studio".to_string()))
    }

    pub fn set_base_url(&self, url: &str) -> Result<()> {
        let mut config = self.load_config()?;
        config.base_url = Some(url.to_string());
        self.save_config(&config)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let config = self.load_config()?;
        Ok(config.settings.get(key).cloned())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let mut config = self.load_config()?;
        config.settings.insert(key.to_string(), value.to_string());
        self.save_config(&config)
    }
}

#[derive(clap::Subcommand)]
pub enum ConfigCommands {
    Get { key: String },
    Set { key: String, value: String },
    List,
}

impl NablaCli {
    pub fn handle_config_command(&mut self, command: ConfigCommands) -> Result<()> {
        match command {
            ConfigCommands::Get { key } => {
                match key.as_str() {
                    "BASE_URL" => {
                        let base_url = self.config_store.get_base_url()?;
                        println!("BASE_URL: {}", base_url);
                    }
                    _ => {
                        if let Some(value) = self.config_store.get_setting(&key)? {
                            println!("{}: {}", key, value);
                        } else {
                            println!("Configuration key '{}' not found", key);
                        }
                    }
                }
            }
            ConfigCommands::Set { key, value } => {
                match key.as_str() {
                    "BASE_URL" => {
                        self.config_store.set_base_url(&value)?;
                        println!("✅ Set BASE_URL to: {}", value);
                    }
                    _ => {
                        self.config_store.set_setting(&key, &value)?;
                        println!("✅ Set {} to: {}", key, value);
                    }
                }
            }
            ConfigCommands::List => {
                let config = self.config_store.load_config()?;
                println!("📋 Configuration:");
                println!("  BASE_URL: {}", config.base_url.unwrap_or_else(|| "https://api.nabla.dev".to_string()));
                
                if !config.settings.is_empty() {
                    println!("  Custom settings:");
                    for (key, value) in &config.settings {
                        println!("    {}: {}", key, value);
                    }
                }
            }
        }
        Ok(())
    }
}