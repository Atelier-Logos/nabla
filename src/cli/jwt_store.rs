use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use std::fs;
use home::home_dir;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

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

    pub fn is_authenticated(&self) -> bool {
        self.load_jwt().unwrap_or(None).is_some()
    }
    
    pub fn verify_and_store_jwt(&self, jwt_token: &str) -> Result<JwtData> {
        // TODO: Replace with your actual signing key - this should be the same key used in your backend
        // For now using a placeholder - you'll need to set this to your actual signing key
        let signing_key = std::env::var("NABLA_JWT_SECRET")
            .map_err(|_| anyhow!("NABLA_JWT_SECRET environment variable is required for JWT verification"))?;
        
        let key = DecodingKey::from_secret(signing_key.as_ref());
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
}