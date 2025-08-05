use nabla_cli::config::{Config, DeploymentType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing Deployment Modes");

    // Test 1: Show current environment config
    println!("\n1. Current Environment Config...");
    let current_config = Config::from_env().unwrap_or_default();
    println!("✅ Current Config:");
    println!("   Deployment: {:?}", current_config.deployment_type);

    println!("   Port: {}", current_config.port);
    println!("   Base URL: {}", current_config.base_url);

    // Test 2: Show deployment type parsing
    println!("\n2. Testing Deployment Type Parsing...");
    let deployments = ["oss", "cloud", "private", "invalid"];
    for deployment in deployments {
        match deployment.parse::<DeploymentType>() {
            Ok(dt) => println!("✅ '{}' → {:?}", deployment, dt),
            Err(e) => println!("❌ '{}' → Error: {}", deployment, e),
        }
    }

    // Test 3: Authentication Requirements
    println!("\n3. Authentication Requirements by Mode:");
    println!("   OSS:     ❌ No auth needed - Direct local access");
    println!("   Cloud:   ✅ Browser OAuth + JWT - Managed service");
    println!("   Private: ✅ JWT only - Self-hosted with auth");

    // Test 4: Feature Availability
    println!("\n4. Feature Matrix:");
    println!("┌─────────────────────┬─────┬───────┬─────────┐");
    println!("│ Feature             │ OSS │ Cloud │ Private │");
    println!("├─────────────────────┼─────┼───────┼─────────┤");
    println!("│ Local Analysis      │  ✅  │   ✅   │    ✅    │");
    println!("│ CLI + TUI           │  ✅  │   ✅   │    ✅    │");
    println!("│ Web Portal          │  ❌  │   ✅   │    ✅    │");
    println!("│ Team Collaboration  │  ❌  │   ✅   │    ✅    │");
    println!("│ Browser Auth        │  ❌  │   ✅   │    ❌    │");
    println!("│ Custom Deployment   │  ❌  │   ❌   │    ✅    │");
    println!("│ SSO Integration     │  ❌  │   ❌   │    ✅    │");
    println!("└─────────────────────┴─────┴───────┴─────────┘");

    // Test 5: Portal URL Generation Examples
    println!("\n5. Portal URL Examples:");
    let examples = [
        ("acme-corp", "550e8400-e29b-41d4-a716-446655440000"),
        ("tech-startup", "123e4567-e89b-12d3-a456-426614174000"),
        ("enterprise-co", "987fcdeb-51a2-43d1-9f12-123456789abc"),
    ];

    for (company, deployment_id) in examples {
        let portal_url = format!("/portal/{}/{}", company, deployment_id);
        println!("   {} → https://nabla.dev{}", company, portal_url);
    }

    // Test 6: Rate Limiting by Plan
    println!("\n6. Rate Limiting by Plan:");
    let rate_limits = [
        ("oss", 100, "Community users"),
        ("cloud", 1000, "Paid cloud users"),
        ("private", 10000, "Enterprise customers"),
    ];

    for (plan, limit, description) in rate_limits {
        println!(
            "   {:>7} plan: {:>5} req/hour - {}",
            plan, limit, description
        );
    }

    // Test 7: Environment Variable Examples
    println!("\n7. Environment Configuration Examples:");
    println!("   OSS Mode:");
    println!("     NABLA_DEPLOYMENT=oss");
    println!("     # No additional config needed");
    println!();
    println!("   Cloud Mode:");
    println!("     NABLA_DEPLOYMENT=cloud");
    println!("     CLERK_PUBLISHABLE_KEY=pk_live_...");
    println!("     BASE_URL=https://api.nabla.dev");
    println!();
    println!("   Private Mode:");
    println!("     NABLA_DEPLOYMENT=private");
    println!("     BASE_URL=https://nabla.yourcompany.com");
    println!("     FIPS_MODE=true");

    // Test 8: JWT Claim Examples
    println!("\n8. JWT Claims Structure:");
    println!("   {{");
    println!("     \"sub\": \"company-name\",           // Company identifier");
    println!("     \"uid\": \"user@company.com\",       // User within company");
    println!("     \"deployment_id\": \"uuid-string\",  // Deployment isolation");
    println!("     \"plan\": \"cloud\",                 // Subscription tier");
    println!("     \"rate_limit\": 1000,               // Requests per hour");
    println!("     \"exp\": 1234567890,                // Expiration timestamp");
    println!("     \"iat\": 1234567890,                // Issued at timestamp");
    println!("     \"jti\": \"jwt-id\"                  // JWT identifier");
    println!("   }}");

    println!("\n🎉 Deployment mode analysis completed!");
    println!("\n💡 To test different modes, set NABLA_DEPLOYMENT environment variable:");
    println!("   NABLA_DEPLOYMENT=oss cargo run --bin nabla-tui");
    println!("   NABLA_DEPLOYMENT=cloud cargo run --bin nabla-tui --features cloud");
    println!("   NABLA_DEPLOYMENT=private cargo run --bin nabla-tui");

    Ok(())
}
