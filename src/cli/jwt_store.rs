use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use home::home_dir;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

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
        // Try environment variable first (fastest)
        if let Ok(key) = std::env::var("LICENSE_SIGNING_KEY") {
            return Ok(key);
        }
        
        // Try Doppler API via HTTP for both OSS and Private deployments
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
                
                if let Ok(response) = ureq::get(&url)
                    .set("Authorization", &format!("Bearer {}", token))
                    .call() 
                {
                    if let Ok(json) = response.into_json::<serde_json::Value>() {
                        if let Some(value) = json.get("value")
                            .and_then(|v| v.get("computed"))
                            .and_then(|c| c.as_str()) 
                        {
                            return Ok(value.to_string());
                        }
                    }
                }
            }
        }
        
        // Final fallback based on deployment type
        let deployment_type = std::env::var("NABLA_DEPLOYMENT")
            .unwrap_or_else(|_| "oss".to_string());

        match deployment_type.to_lowercase().as_str() {
            "oss" => {
                // Hardcoded public key for OSS deployments as last resort
                Ok("t6eLp6y0Ly8BZJIVv_wK71WyBtJ1zY2Pxz2M_0z5t8Q".to_string())
            }
            "private" => {
                Err(anyhow!("LICENSE_SIGNING_KEY required for private deployment (try Doppler CLI or env var)"))
            }
            _ => {
                // Invalid deployment type, try OSS fallback
                Ok("t6eLp6y0Ly8BZJIVv_wK71WyBtJ1zY2Pxz2M_0z5t8Q".to_string())
            }
        }
    }
}
