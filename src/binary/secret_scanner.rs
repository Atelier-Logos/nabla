use aho_corasick::AhoCorasick;
use regex::Regex;
use entropy::shannon_entropy;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretMatch {
    pub rule_name: String,
    pub matched_text: String,
    pub confidence: f64,
    pub offset: usize,
    pub context: String, // Surrounding text for context
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretScanResult {
    pub secrets: Vec<SecretMatch>,
    pub scan_time_ms: u64,
    pub total_entropy_score: f64,
}

pub struct SecretScanner {
    patterns: Vec<SecretPattern>,
    aho_corasick: AhoCorasick,
    keywords: Vec<String>,
}

#[derive(Debug, Clone)]
struct SecretPattern {
    name: String,
    regex: Regex,
    confidence: f64,
}

impl SecretScanner {
    pub fn new() -> anyhow::Result<Self> {
        let patterns = vec![
            SecretPattern {
                name: "AWS Access Key".to_string(),
                regex: Regex::new(r"AKIA[0-9A-Z]{16}")?,
                confidence: 0.9,
            },
            SecretPattern {
                name: "AWS Secret Key".to_string(),
                regex: Regex::new(r"[A-Za-z0-9/+=]{40}")?,
                confidence: 0.7,
            },
            SecretPattern {
                name: "GitHub Token".to_string(),
                regex: Regex::new(r"ghp_[A-Za-z0-9]{36}")?,
                confidence: 0.95,
            },
            SecretPattern {
                name: "GitHub Classic Token".to_string(),
                regex: Regex::new(r"[a-f0-9]{40}")?,
                confidence: 0.6,
            },
            SecretPattern {
                name: "Google API Key".to_string(),
                regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}")?,
                confidence: 0.9,
            },
            SecretPattern {
                name: "RSA Private Key".to_string(),
                regex: Regex::new(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")?,
                confidence: 0.95,
            },
            SecretPattern {
                name: "SSH Private Key".to_string(),
                regex: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----")?,
                confidence: 0.95,
            },
            SecretPattern {
                name: "JWT Token".to_string(),
                regex: Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")?,
                confidence: 0.8,
            },
            SecretPattern {
                name: "Generic API Key".to_string(),
                regex: Regex::new(r#"['"][a-zA-Z0-9_-]{24,}['"]"#)?,
                confidence: 0.4,
            },
            SecretPattern {
                name: "Base64 Encoded".to_string(),
                regex: Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}")?,
                confidence: 0.3,
            },
            SecretPattern {
                name: "Hex Encoded".to_string(),
                regex: Regex::new(r"[a-fA-F0-9]{32,}")?,
                confidence: 0.3,
            },
            SecretPattern {
                name: "Email Address".to_string(),
                regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")?,
                confidence: 0.2,
            },
            SecretPattern {
                name: "URL with Credentials".to_string(),
                regex: Regex::new(r"https?://[^:]+:[^@]+@[^\s]+")?,
                confidence: 0.8,
            },
            SecretPattern {
                name: "Database Connection String".to_string(),
                regex: Regex::new(r"(?:mongodb|mysql|postgresql|redis)://[^\s]+")?,
                confidence: 0.7,
            },
        ];

        // Keywords for Aho-Corasick for fast initial filtering
        let keywords = vec![
            "password", "passwd", "pass", "secret", "key", "token", "auth", "api_key",
            "apikey", "access_key", "private_key", "priv_key", "client_secret", 
            "client_id", "auth_token", "bearer", "authorization", "credential",
            "AKIA", "ghp_", "AIza", "-----BEGIN", "eyJ",
        ];

        let aho_corasick = AhoCorasick::new(&keywords)?;

        Ok(SecretScanner {
            patterns,
            aho_corasick,
            keywords: keywords.into_iter().map(|s| s.to_string()).collect(),
        })
    }

    pub fn scan_binary(&self, contents: &[u8]) -> anyhow::Result<SecretScanResult> {
        let start_time = std::time::Instant::now();
        
        // Convert binary to string, handling non-UTF8 bytes
        let text = String::from_utf8_lossy(contents);
        
        let mut secrets = Vec::new();
        let mut total_entropy: f64 = 0.0;
        
        // First pass: use Aho-Corasick for fast keyword detection
        let keyword_matches: Vec<_> = self.aho_corasick.find_iter(&*text).collect();
        
        if !keyword_matches.is_empty() {
            // Second pass: run regex patterns around keyword matches
            for pattern in &self.patterns {
                for regex_match in pattern.regex.find_iter(&text) {
                    let matched_text = regex_match.as_str();
                    let offset = regex_match.start();
                    
                    // Calculate entropy for this match
                    let entropy = shannon_entropy(matched_text.as_bytes());
                    total_entropy += entropy as f64;
                    
                    // Adjust confidence based on entropy
                    let entropy_factor = if entropy > 4.5 { 1.2 } else if entropy < 2.0 { 0.8 } else { 1.0 };
                    let confidence = (pattern.confidence * entropy_factor).min(1.0);
                    
                    // Skip low-entropy matches for generic patterns
                    if pattern.name.contains("Generic") && entropy < 3.5 {
                        continue;
                    }
                    
                    // Extract context around the match
                    let context_start = offset.saturating_sub(20);
                    let context_end = (offset + matched_text.len() + 20).min(text.len());
                    let context = text[context_start..context_end].to_string();
                    
                    secrets.push(SecretMatch {
                        rule_name: pattern.name.clone(),
                        matched_text: matched_text.to_string(),
                        confidence,
                        offset,
                        context,
                    });
                }
            }
        }

        // Scan for high-entropy strings that might be secrets
        let high_entropy_secrets = self.scan_high_entropy_strings(&text)?;
        total_entropy += high_entropy_secrets.iter()
            .map(|s| shannon_entropy(s.matched_text.as_bytes()) as f64)
            .sum::<f64>();
        secrets.extend(high_entropy_secrets);
        
        // Remove duplicates and sort by confidence
        secrets.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        secrets.dedup_by(|a, b| a.matched_text == b.matched_text);
        
        // Limit results to prevent overwhelming output
        secrets.truncate(50);
        
        let scan_time_ms = start_time.elapsed().as_millis() as u64;
        
        Ok(SecretScanResult {
            secrets,
            scan_time_ms,
            total_entropy_score: total_entropy as f64,
        })
    }

    fn scan_high_entropy_strings(&self, text: &str) -> anyhow::Result<Vec<SecretMatch>> {
        let mut secrets = Vec::new();
        
        // Look for strings with high entropy that might be encoded secrets
        let words: Vec<&str> = text.split_whitespace().collect();
        
        for word in words {
            if word.len() >= 16 && word.len() <= 128 {
                let entropy = shannon_entropy(word.as_bytes());
                
                // High entropy threshold for potential secrets
                if entropy > 4.8 {
                    // Additional checks to reduce false positives
                    let has_mixed_case = word.chars().any(|c| c.is_ascii_lowercase()) 
                        && word.chars().any(|c| c.is_ascii_uppercase());
                    let has_numbers = word.chars().any(|c| c.is_ascii_digit());
                    let has_special = word.chars().any(|c| !c.is_alphanumeric());
                    
                    let complexity_score = [has_mixed_case, has_numbers, has_special]
                        .iter()
                        .map(|&b| if b { 1 } else { 0 })
                        .sum::<i32>();
                    
                    if complexity_score >= 2 {
                        let confidence = ((entropy - 4.0) / 4.0).min(0.8) as f64;
                        
                        if let Some(offset) = text.find(word) {
                            let context_start = offset.saturating_sub(10);
                            let context_end = (offset + word.len() + 10).min(text.len());
                            let context = text[context_start..context_end].to_string();
                            
                            secrets.push(SecretMatch {
                                rule_name: format!("High Entropy String ({})", entropy.round()),
                                matched_text: word.to_string(),
                                confidence,
                                offset,
                                context,
                            });
                        }
                    }
                }
            }
        }
        
        Ok(secrets)
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new().expect("Failed to create default SecretScanner")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_scanner_creation() {
        let scanner = SecretScanner::new();
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_aws_key_detection() {
        let scanner = SecretScanner::new().unwrap();
        let test_data = b"AKIAIOSFODNN7EXAMPLE is an AWS key";
        let result = scanner.scan_binary(test_data).unwrap();
        
        assert!(!result.secrets.is_empty());
        assert!(result.secrets.iter().any(|s| s.rule_name.contains("AWS")));
    }

    #[test]
    fn test_github_token_detection() {
        let scanner = SecretScanner::new().unwrap();
        let test_data = b"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = scanner.scan_binary(test_data).unwrap();
        
        assert!(!result.secrets.is_empty());
        assert!(result.secrets.iter().any(|s| s.rule_name.contains("GitHub")));
    }

    #[test]
    fn test_high_entropy_detection() {
        let scanner = SecretScanner::new().unwrap();
        let test_data = b"random text Kj2Hf9pQw8Rz3mN7vX5cT1gY4eS6bU0o more text";
        let result = scanner.scan_binary(test_data).unwrap();
        
        // Should detect high entropy string
        assert!(result.total_entropy_score > 0.0);
    }
}
