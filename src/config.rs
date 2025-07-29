use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum DeploymentType {
    OSS,
    Cloud,
    Private,
}

impl std::str::FromStr for DeploymentType {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "oss" => Ok(DeploymentType::OSS),
            "cloud" => Ok(DeploymentType::Cloud),
            "private" => Ok(DeploymentType::Private),
            _ => Err(anyhow::anyhow!("Invalid deployment type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub port: u16,
    pub base_url: String,
    pub fips_mode: bool,
    pub fips_validation: bool,
    pub deployment_type: DeploymentType,
    #[cfg(feature = "cloud")]
    pub clerk_publishable_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8080,
            base_url: "http://localhost:8080".to_string(),
            fips_mode: false,
            fips_validation: false,
            deployment_type: DeploymentType::OSS,
            #[cfg(feature = "cloud")]
            clerk_publishable_key: None,
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        
        let deployment_type = std::env::var("NABLA_DEPLOYMENT")
            .unwrap_or_else(|_| "oss".to_string())
            .parse()?;
        
        let config = Config {
            port: std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse()?,
            base_url: std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
            fips_mode: std::env::var("FIPS_MODE").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            fips_validation: std::env::var("FIPS_VALIDATION").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            deployment_type,
            #[cfg(feature = "cloud")]
            clerk_publishable_key: std::env::var("CLERK_PUBLISHABLE_KEY").ok(),
        };

        Ok(config)
    }
} 