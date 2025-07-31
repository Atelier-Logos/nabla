use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;
use anyhow::{Result, anyhow};

/// SSRF protection configuration
#[derive(Debug, Clone)]
pub struct SSRFConfig {
    /// Whitelisted domains that are allowed
    pub whitelisted_domains: HashSet<String>,
    /// Whitelisted IP ranges (CIDR notation)
    pub whitelisted_ips: HashSet<String>,
    /// Whether to allow localhost
    pub allow_localhost: bool,
    /// Whether to allow private IPs
    pub allow_private_ips: bool,
}

impl Default for SSRFConfig {
    fn default() -> Self {
        let mut whitelisted_domains = HashSet::new();
        
        // AWS Marketplace domains
        whitelisted_domains.insert("platform.atelierlogos.studio".to_string());
        whitelisted_domains.insert("nabla.atelierlogos.studio".to_string());
        whitelisted_domains.insert("custom.nabla.com".to_string());
        whitelisted_domains.insert("aws.amazon.com".to_string());
        whitelisted_domains.insert("marketplace.amazonaws.com".to_string());
        
        // OpenAI and common AI providers
        whitelisted_domains.insert("api.openai.com".to_string());
        whitelisted_domains.insert("api.together.xyz".to_string());
        whitelisted_domains.insert("api.anthropic.com".to_string());
        whitelisted_domains.insert("api.groq.com".to_string());
        
        // Hugging Face
        whitelisted_domains.insert("huggingface.co".to_string());
        whitelisted_domains.insert("hf-mirror.com".to_string());
        
        // Common local inference servers
        whitelisted_domains.insert("localhost".to_string());
        whitelisted_domains.insert("127.0.0.1".to_string());
        whitelisted_domains.insert("0.0.0.0".to_string());
        
        let mut whitelisted_ips = HashSet::new();
        whitelisted_ips.insert("127.0.0.1/32".to_string());
        whitelisted_ips.insert("::1/128".to_string());
        
        Self {
            whitelisted_domains,
            whitelisted_ips,
            allow_localhost: true,
            allow_private_ips: false,
        }
    }
}

/// SSRF protection validator
#[derive(Debug, Clone)]
pub struct SSRFValidator {
    config: SSRFConfig,
}

impl SSRFValidator {
    /// Create a new SSRF validator with default configuration
    pub fn new() -> Self {
        Self {
            config: SSRFConfig::default(),
        }
    }
    
    /// Create a new SSRF validator with custom configuration
    
    /// Validate a URL for SSRF protection
    pub fn validate_url(&self, url_str: &str) -> Result<Url, anyhow::Error> {
        // Parse the URL
        let url = Url::parse(url_str)
            .map_err(|e| anyhow!("Invalid URL format: {}", e))?;
        
        // Check if it's a valid scheme
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(anyhow!("Only HTTP and HTTPS schemes are allowed"));
        }
        
        // Check for URL manipulation attempts
        if url.username() != "" || url.password().is_some() {
            return Err(anyhow!("URLs with user credentials are not allowed"));
        }
        
        // Check for suspicious fragments that might indicate manipulation
        if let Some(fragment) = url.fragment() {
            if fragment.contains("@") || fragment.contains("%") {
                return Err(anyhow!("Suspicious URL fragment detected"));
            }
        }
        
        // Extract host
        let host = url.host_str()
            .ok_or_else(|| anyhow!("URL must have a host"))?;
        
        // Check for IP addresses first
        if let Some(ip) = self.parse_ip(host) {
            if !self.is_ip_allowed(&ip) {
                return Err(anyhow!("IP address '{}' is not allowed", ip));
            }
        } else {
            // For domain names, check if host is in whitelist
            if !self.is_host_whitelisted(host) {
                return Err(anyhow!("Host '{}' is not in the whitelist", host));
            }
        }
        
        // Check for localhost
        if !self.config.allow_localhost && self.is_localhost(host) {
            return Err(anyhow!("Localhost is not allowed"));
        }
        
        // Check for dangerous ports on localhost
        if self.is_localhost(host) && self.has_dangerous_port(&url) {
            return Err(anyhow!("Access to dangerous localhost port is not allowed"));
        }
        
        Ok(url)
    }
    
    /// Check if a host is whitelisted
    fn is_host_whitelisted(&self, host: &str) -> bool {
        // Check exact match
        if self.config.whitelisted_domains.contains(host) {
            return true;
        }
        
        // Check subdomain matches
        for whitelisted in &self.config.whitelisted_domains {
            if host.ends_with(&format!(".{}", whitelisted)) {
                return true;
            }
        }
        
        false
    }
    
    /// Parse IP address from host string
    fn parse_ip(&self, host: &str) -> Option<IpAddr> {
        host.parse::<IpAddr>().ok()
    }
    
    /// Check if an IP address is allowed
    fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        // Check whitelisted IP ranges first
        for whitelisted in &self.config.whitelisted_ips {
            if self.ip_in_cidr(ip, whitelisted) {
                return true;
            }
        }
        
        match ip {
            IpAddr::V4(ipv4) => self.is_ipv4_allowed(ipv4),
            IpAddr::V6(ipv6) => self.is_ipv6_allowed(ipv6),
        }
    }
    
    /// Check if IPv4 address is allowed
    fn is_ipv4_allowed(&self, ip: &Ipv4Addr) -> bool {
        // Check if it's localhost
        if ip.octets() == [127, 0, 0, 1] {
            return self.config.allow_localhost;
        }
        
        // Check if it's private and private IPs are allowed
        if self.is_private_ipv4(ip) {
            return self.config.allow_private_ips;
        }
        
        // For public IPs, they should be explicitly whitelisted as domains
        false
    }
    
    /// Check if IPv6 address is allowed
    fn is_ipv6_allowed(&self, ip: &Ipv6Addr) -> bool {
        // Check if it's localhost
        if ip.segments() == [0, 0, 0, 0, 0, 0, 0, 1] {
            return self.config.allow_localhost;
        }
        
        // Check if it's private and private IPs are allowed
        if self.is_private_ipv6(ip) {
            return self.config.allow_private_ips;
        }
        
        // For public IPs, they should be explicitly whitelisted as domains
        false
    }
    
    /// Check if IPv4 address is private
    fn is_private_ipv4(&self, ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();
        
        // Private ranges
        (octets[0] == 10) || // 10.0.0.0/8
        (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) || // 172.16.0.0/12
        (octets[0] == 192 && octets[1] == 168) || // 192.168.0.0/16
        (octets[0] == 127) || // 127.0.0.0/8 (localhost)
        (octets[0] == 0) || // 0.0.0.0/8
        (octets[0] == 169 && octets[1] == 254) || // 169.254.0.0/16 (link-local)
        (octets[0] == 224) || // 224.0.0.0/4 (multicast)
        (octets[0] == 240) // 240.0.0.0/4 (reserved)
    }
    
    /// Check if IPv6 address is private
    fn is_private_ipv6(&self, ip: &Ipv6Addr) -> bool {
        let segments = ip.segments();
        
        // Localhost
        if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
            return true;
        }
        
        // Link-local
        if segments[0] == 0xfe80 {
            return true;
        }
        
        // Unique local
        if segments[0] & 0xfe00 == 0xfc00 {
            return true;
        }
        
        // Multicast
        if segments[0] & 0xff00 == 0xff00 {
            return true;
        }
        
        false
    }
    
    /// Check if IP is in CIDR range
    fn ip_in_cidr(&self, ip: &IpAddr, cidr: &str) -> bool {
        // Simple implementation - in production, use a proper CIDR library
        if let Some((network, bits_str)) = cidr.split_once('/') {
            if let (Ok(network_ip), Ok(bits)) = (network.parse::<IpAddr>(), bits_str.parse::<u8>()) {
                match (ip, &network_ip) {
                    (IpAddr::V4(ip_v4), IpAddr::V4(net_v4)) => {
                        // Simple IPv4 CIDR matching
                        let ip_bits = u32::from_be_bytes(ip_v4.octets());
                        let net_bits = u32::from_be_bytes(net_v4.octets());
                        let mask = !((1u32 << (32 - bits)) - 1);
                        (ip_bits & mask) == (net_bits & mask)
                    },
                    (IpAddr::V6(_), IpAddr::V6(_)) => {
                        // For IPv6, just do exact match for now
                        ip == &network_ip
                    },
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }
    
    /// Check if host is localhost
    fn is_localhost(&self, host: &str) -> bool {
        host == "localhost" || 
        host == "127.0.0.1" || 
        host == "::1" ||
        host.starts_with("localhost:")
    }
    
    /// Check if URL has a dangerous port
    fn has_dangerous_port(&self, url: &Url) -> bool {
        if let Some(port) = url.port() {
            // Common dangerous ports
            matches!(port, 
                22 |   // SSH
                23 |   // Telnet
                25 |   // SMTP
                53 |   // DNS
                110 |  // POP3
                143 |  // IMAP
                993 |  // IMAPS
                995 |  // POP3S
                1433 | // MSSQL
                3306 | // MySQL
                3389 | // RDP
                5432 | // PostgreSQL
                5984 | // CouchDB
                6379 | // Redis
                7000 | // Cassandra
                7001 | // Cassandra SSL
                8086 | // InfluxDB
                9042 | // Cassandra
                9160 | // Cassandra Thrift
                9200 | // Elasticsearch
                9300 | // Elasticsearch
                11211 | // Memcached
                27017 | // MongoDB
                27018 | // MongoDB
                27019  // MongoDB
            )
        } else {
            false
        }
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_whitelisted_domains() {
        let validator = SSRFValidator::new();
        
        // Test whitelisted domains
        assert!(validator.validate_url("https://api.openai.com/v1/chat/completions").is_ok());
        assert!(validator.validate_url("https://platform.atelierlogos.studio/marketplace/register").is_ok());
        assert!(validator.validate_url("https://aws.amazon.com/marketplace/listing").is_ok());
        
        // Test non-whitelisted domains
        assert!(validator.validate_url("https://evil.com/api").is_err());
        assert!(validator.validate_url("https://malicious.example.com/").is_err());
    }
    
    #[test]
    fn test_localhost() {
        let mut validator = SSRFValidator::new();
        
        // Test localhost with allow_localhost = true
        assert!(validator.validate_url("http://localhost:11434/completion").is_ok());
        assert!(validator.validate_url("http://127.0.0.1:8080/api").is_ok());
        
        // Test localhost with allow_localhost = false
        validator.config.allow_localhost = false;
        assert!(validator.validate_url("http://localhost:11434/completion").is_err());
        assert!(validator.validate_url("http://127.0.0.1:8080/api").is_err());
    }
    
    #[test]
    fn test_private_ips() {
        let mut validator = SSRFValidator::new();
        
        // Test private IPs with allow_private_ips = false
        assert!(validator.validate_url("http://192.168.1.1:8080/api").is_err());
        assert!(validator.validate_url("http://10.0.0.1:8080/api").is_err());
        assert!(validator.validate_url("http://172.16.0.1:8080/api").is_err());
        
        // Test private IPs with allow_private_ips = true
        validator.config.allow_private_ips = true;
        assert!(validator.validate_url("http://192.168.1.1:8080/api").is_ok());
        assert!(validator.validate_url("http://10.0.0.1:8080/api").is_ok());
        assert!(validator.validate_url("http://172.16.0.1:8080/api").is_ok());
    }
    
    #[test]
    fn test_invalid_urls() {
        let validator = SSRFValidator::new();
        
        // Test invalid schemes
        assert!(validator.validate_url("ftp://example.com").is_err());
        assert!(validator.validate_url("file:///etc/passwd").is_err());
        
        // Test invalid URLs
        assert!(validator.validate_url("not-a-url").is_err());
        assert!(validator.validate_url("http://").is_err());
    }
} 