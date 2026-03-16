use tracing::{info, warn};

/// Validates whether the provided token matches the expected NETSAGE_AUTH_TOKEN.
pub fn validate_token(token: &str) -> bool {
    let expected = std::env::var("NETSAGE_AUTH_TOKEN").unwrap_or_else(|_| "netsage_default_secret".to_string());
    
    if token == expected {
        info!("Authentication successful for remote node.");
        true
    } else {
        warn!("Authentication failed: Invalid token provided.");
        false
    }
}

pub fn get_local_token() -> String {
    std::env::var("NETSAGE_AUTH_TOKEN").unwrap_or_else(|_| "netsage_default_secret".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_validation() {
        std::env::set_var("NETSAGE_AUTH_TOKEN", "test_secret");
        assert!(validate_token("test_secret"));
        assert!(!validate_token("wrong_secret"));
    }
}
