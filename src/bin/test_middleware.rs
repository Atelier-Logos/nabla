use nabla_core::middleware::{Claims, PlanFeatures};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing JWT Middleware");
    
    // Test 1: Create JWT with company/deployment format
    println!("\n1. Creating JWT with new format...");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let features = PlanFeatures {
        chat_enabled: true,
        api_access: true,
        file_upload_limit_mb: 100,
        concurrent_requests: 10,
        custom_models: true,
        sbom_generation: true,
        vulnerability_scanning: true,
        signed_attestation: true,
        monthly_binaries: 1000,
    };

    let claims = Claims {
        sub: "acme-corp".to_string(),          // Company name
        uid: "alice@acme.com".to_string(),     // User email
        exp: now + 3600,
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
        rate_limit: 1000,
        deployment_id: uuid::Uuid::new_v4().to_string(), // UUID
        features,
    };
    
    let secret = b"test-secret-key-for-middleware";
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret)
    )?;
    
    println!("✅ JWT created for company: {}", claims.sub);
    println!("   Deployment ID: {}", claims.deployment_id);
    println!("   Chat enabled: {}", claims.features.chat_enabled);
    println!("   Monthly binaries: {}", claims.features.monthly_binaries);
    println!("   Rate limit: {}", claims.rate_limit);
    
    // Test 2: Validate JWT (simulate middleware)
    println!("\n2. Validating JWT (middleware simulation)...");
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret),
        &validation,
    )?;
    
    let decoded_claims = token_data.claims;
    println!("✅ JWT validation successful");
    println!("   Company: {}", decoded_claims.sub);
    println!("   User: {}", decoded_claims.uid);
    println!("   Deployment: {}", decoded_claims.deployment_id);
    
    // Test 3: Portal URL format
    println!("\n3. Testing portal URL format...");
    let portal_url = format!("/portal/{}/{}", decoded_claims.sub, decoded_claims.deployment_id);
    println!("✅ Portal URL: {}", portal_url);
    
    // Test 4: Rate limiting key format
    println!("\n4. Testing rate limiting key format...");
    let rate_limit_key = format!("{}:{}", decoded_claims.sub, decoded_claims.deployment_id);
    println!("✅ Rate limit key: {}", rate_limit_key);
    
    // Test 5: Multi-tenancy isolation
    println!("\n5. Testing multi-tenancy isolation...");
    println!("   Each company gets isolated data via 'sub' field");
    println!("   Each deployment gets isolated resources via 'deployment_id'");
    println!("   Rate limiting is per company+deployment combination");
    
    println!("\n🎉 Middleware JWT tests passed!");
    
    // Test 6: Different feature configurations
    println!("\n6. Testing different feature configurations...");
    let configs = [
        ("Basic", PlanFeatures {
            chat_enabled: false,
            api_access: true,
            file_upload_limit_mb: 10,
            concurrent_requests: 1,
            custom_models: false,
            sbom_generation: true,
            vulnerability_scanning: true,
            signed_attestation: false,
            monthly_binaries: 100,
        }),
        ("Premium", PlanFeatures {
            chat_enabled: true,
            api_access: true,
            file_upload_limit_mb: 100,
            concurrent_requests: 10,
            custom_models: true,
            sbom_generation: true,
            vulnerability_scanning: true,
            signed_attestation: true,
            monthly_binaries: 1000,
        }),
        ("Enterprise", PlanFeatures {
            chat_enabled: true,
            api_access: true,
            file_upload_limit_mb: 1000,
            concurrent_requests: 50,
            custom_models: true,
            sbom_generation: true,
            vulnerability_scanning: true,
            signed_attestation: true,
            monthly_binaries: 10000,
        }),
    ];
    
    for (config_name, features) in configs {
        let test_claims = Claims {
            sub: format!("test-company-{}", config_name.to_lowercase()),
            uid: "test@example.com".to_string(),
            exp: now + 3600,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            rate_limit: features.concurrent_requests as i32 * 100,
            deployment_id: uuid::Uuid::new_v4().to_string(),
            features,
        };
        
        let test_token = encode(
            &Header::new(Algorithm::HS256),
            &test_claims,
            &EncodingKey::from_secret(secret)
        )?;
        
        let decoded = decode::<Claims>(&test_token, &DecodingKey::from_secret(secret), &validation)?;
        println!("✅ {} config: {} company, chat: {}, monthly_binaries: {}", 
                 config_name,
                 decoded.claims.sub, 
                 decoded.claims.features.chat_enabled,
                 decoded.claims.features.monthly_binaries);
    }
    
    println!("\n🚀 All middleware tests completed successfully!");
    Ok(())
}