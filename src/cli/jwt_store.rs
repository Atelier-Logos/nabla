use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use home::home_dir;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[cfg(feature = "private")]
use doppler_rs::{apis::client::Client, apis::Error as DopplerError};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtData {
    pub token: String,
    pub sub: String,
    pub deployment_id: String,
    pub expires_at: i64,
    pub features: PlanFeatures,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlanFeatures {
    pub chat_enabled: bool,
    pub api_access: bool,
    pub file_upload_limit_mb: u32,
    pub concurrent_requests: u32,
    pub custom_models: bool,
    pub sbom_generation: bool,
    pub vulnerability_scanning: bool,
    pub signed_attestation: bool,
    pub monthly_binaries: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    pub sub: String,
    pub deployment_id: String,
    pub exp: i64,
    pub features: PlanFeatures,
}

pub struct JwtStore {
    store_path: PathBuf,
}

impl JwtStore {
    pub fn new() -> Result<Self> {
        let home = home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
        let nabla_dir = home.join(".nabla");

        if !nabla_dir.exists() {
            fs::create_dir_all(&nabla_dir)?;
        }

        Ok(Self {
            store_path: nabla_dir.join("jwt.json"),
        })
    }

    pub fn save_jwt(&self, jwt_data: &JwtData) -> Result<()> {
        let json = serde_json::to_string_pretty(jwt_data)?;
        fs::write(&self.store_path, json)?;
        Ok(())
    }

    pub fn load_jwt(&self) -> Result<Option<JwtData>> {
        if !self.store_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.store_path)?;
        let jwt_data: JwtData = serde_json::from_str(&content)?;

        // Check if token is expired
        let now = chrono::Utc::now().timestamp();
        if jwt_data.expires_at < now {
            self.clear_jwt()?;
            return Ok(None);
        }

        Ok(Some(jwt_data))
    }

    pub fn clear_jwt(&self) -> Result<()> {
        if self.store_path.exists() {
            fs::remove_file(&self.store_path)?;
        }
        Ok(())
    }

    pub fn verify_and_store_jwt(&self, jwt_token: &str) -> Result<JwtData> {
        // Get signing key using the same logic as config.rs
        let signing_key_b64 = self.get_license_signing_key()?;

        // Decode the base64 key like the minting tool does
        let key_bytes = general_purpose::URL_SAFE_NO_PAD.decode(signing_key_b64.trim())
            .map_err(|e| anyhow!("Failed to decode LICENSE_SIGNING_KEY as base64: {}", e))?;

        let key = DecodingKey::from_secret(&key_bytes);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        // Decode and verify the JWT
        let token_data = decode::<JwtClaims>(jwt_token, &key, &validation)
            .map_err(|e| anyhow!("JWT verification failed: {}", e))?;

        let claims = token_data.claims;

        let jwt_data = JwtData {
            token: jwt_token.to_string(),
            sub: claims.sub,
            deployment_id: claims.deployment_id,
            expires_at: claims.exp,
            features: claims.features,
        };

        // Store the verified JWT
        self.save_jwt(&jwt_data)?;

        Ok(jwt_data)
    }

    fn get_license_signing_key(&self) -> Result<String> {
        // Determine deployment type
        let deployment_type = std::env::var("NABLA_DEPLOYMENT")
            .unwrap_or_else(|_| "oss".to_string());

        match deployment_type.to_lowercase().as_str() {
            "oss" => {
                // Use default OSS key
                Ok("t6eLp6y0Ly8BZJIVv_wK71WyBtJ1zY2Pxz2M_0z5t8Q".to_string())
            }
            "private" => {
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
                    .map_err(|_| anyhow!("LICENSE_SIGNING_KEY environment variable is required for JWT verification"))
            }
            _ => {
                // Invalid deployment type, fallback to environment variable
                std::env::var("LICENSE_SIGNING_KEY")
                    .map_err(|_| anyhow!("LICENSE_SIGNING_KEY environment variable is required for JWT verification"))
            }
        }
    }
}
