use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum DeploymentType {
    OSS,
    NablaSecure,
}

impl std::str::FromStr for DeploymentType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "oss" => Ok(DeploymentType::OSS),
            "nablasecure" | "nabla-secure" | "secure" => Ok(DeploymentType::NablaSecure),
            _ => Err(anyhow::anyhow!("Invalid deployment type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub port: u16,
    pub base_url: String,
    pub deployment_type: DeploymentType,
    pub enterprise_features: bool,
    pub license_signing_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8080,
            base_url: "http://localhost:8080".to_string(),
            deployment_type: DeploymentType::OSS,
            enterprise_features: false, // OSS defaults to no enterprise features
            license_signing_key: "t6eLp6y0Ly8BZJIVv_wK71WyBtJ1zY2Pxz2M_0z5t8Q".to_string(),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let deployment_type = std::env::var("NABLA_DEPLOYMENT")
            .unwrap_or_else(|_| "oss".to_string())
            .parse()?;

        let enterprise_features = std::env::var("NABLA_ENTERPRISE_FEATURES")
            .unwrap_or_else(|_| match deployment_type {
                DeploymentType::NablaSecure => "true".to_string(),
                DeploymentType::OSS => "false".to_string(),
            })
            .parse()
            .unwrap_or(false);

        let license_signing_key = Self::get_license_signing_key(&deployment_type)?;
        
        let config = Config {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            deployment_type,
            enterprise_features,
            license_signing_key,
        };

        Ok(config)
    }

    fn get_license_signing_key(deployment_type: &DeploymentType) -> Result<String> {
        // Try environment variable first (fastest)
        if let Ok(key) = std::env::var("LICENSE_SIGNING_KEY") {
            return Ok(key);
        }
        
        // Try Doppler API via HTTP for both OSS and NablaSecure deployments
        if let (Ok(project), Ok(config_name)) = (
            std::env::var("DOPPLER_PROJECT"),
            std::env::var("DOPPLER_CONFIG")
        ) {
            // Try deployment-specific token first, then fall back to general token
            let doppler_token = if config_name.contains("prd") {
                std::env::var("DOPPLER_TOKEN_PRD")
                    .or_else(|_| std::env::var("DOPPLER_TOKEN"))
            } else if config_name.contains("oss") {
                std::env::var("DOPPLER_TOKEN_OSS")
                    .or_else(|_| std::env::var("DOPPLER_TOKEN"))
            } else {
                std::env::var("DOPPLER_TOKEN")
            };
            
            if let Ok(token) = doppler_token {
                
                // Use ureq for sync HTTP requests (no runtime conflicts)
                let url = format!("https://api.doppler.com/v3/configs/config/secret?project={}&config={}&name=LICENSE_SIGNING_KEY", 
                    project, config_name);
                
                match ureq::get(&url)
                    .set("Authorization", &format!("Bearer {}", token))
                    .call() 
            {
                Ok(response) => {
                    match response.into_json::<serde_json::Value>() {
                        Ok(json) => {
                            if let Some(value) = json.get("value")
                                .and_then(|v| v.get("computed"))
                                .and_then(|c| c.as_str()) 
                            {
                                return Ok(value.to_string());
                            }
                        }
                        Err(_) => {}
                    }
                }
                Err(_) => {}
            }
            }
        }
        
        // Final fallback based on deployment type
        match deployment_type {
            DeploymentType::OSS => {
                // Hardcoded public key for OSS deployments as last resort
                Ok("t6eLp6y0Ly8BZJIVv_wK71WyBtJ1zY2Pxz2M_0z5t8Q".to_string())
            }
            DeploymentType::NablaSecure => {
                Err(anyhow::anyhow!("LICENSE_SIGNING_KEY required for NablaSecure deployment (try Doppler or env var)"))
            }
        }
    }
}
