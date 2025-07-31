use anyhow::Result;
use serde::Deserialize;

#[cfg(feature = "private")]
use doppler_rs::{apis::client::Client, apis::Error as DopplerError};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum DeploymentType {
    OSS,
    Private,
}

impl std::str::FromStr for DeploymentType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "oss" => Ok(DeploymentType::OSS),
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
    pub license_signing_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8080,
            base_url: "http://localhost:8080".to_string(),
            fips_mode: false,
            fips_validation: false,
            deployment_type: DeploymentType::OSS,
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

        let license_signing_key = Self::get_license_signing_key(&deployment_type)?;
        
        let config = Config {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            fips_mode: std::env::var("FIPS_MODE")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            fips_validation: std::env::var("FIPS_VALIDATION")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            deployment_type,
            license_signing_key,
        };

        Ok(config)
    }

    fn get_license_signing_key(deployment_type: &DeploymentType) -> Result<String> {
        match deployment_type {
            DeploymentType::OSS => {
                // Public key for OSS deployments
                Ok("t6eLp6y0Ly8BZJIVv_wK71WyBtJ1zY2Pxz2M_0z5t8Q".to_string())
            }
            DeploymentType::Private => {
                #[cfg(feature = "private")]
                {
                    // Try Doppler first for private deployments
                    if let (Ok(project), Ok(config_name)) = (
                        std::env::var("DOPPLER_PROJECT"),
                        std::env::var("DOPPLER_CONFIG")
                    ) {
                        if let Ok(doppler_token) = std::env::var("DOPPLER_TOKEN") {
                            let client = Client::new(&doppler_token);
                            if let Ok(secret) = client.get_secret(&project, &config_name, "LICENSE_SIGNING_KEY") {
                                return Ok(secret.value);
                            }
                        }
                    }
                }
                
                // Fallback to environment variable
                std::env::var("LICENSE_SIGNING_KEY")
                    .map_err(|_| anyhow::anyhow!("LICENSE_SIGNING_KEY env missing for private deployment"))
            }
        }
    }
}
