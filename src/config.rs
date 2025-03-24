use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use pqcrypto_dilithium::dilithium5::{PublicKey, SecretKey};
use pqcrypto_traits::sign::{PublicKey as OtherPublicKey, SecretKey as OtherSecretKey};
use std::env;

/// Configuration settings
pub struct Config {
    pub ipfs_node: String,
    pub database_url: String,
    pub bind_address: String,
    // Base64-encoded public key
    dilithium_public_key: String,
    // Base64-encoded secret key
    dilithium_secret_key: String,
    pub max_concurrent_uploads: usize,
}

impl Config {
    /// Loads configuration from environment variables
    pub fn from_env() -> Result<Self, env::VarError> {
        dotenv::dotenv().ok();

        // Default maximum concurrent uploads
        const DEFAULT_MAX_CONCURRENT_UPLOADS: usize = 42;

        let max_concurrent_uploads = env::var("MAX_CONCURRENT_UPLOADS")
            .unwrap_or_else(|_| DEFAULT_MAX_CONCURRENT_UPLOADS.to_string())
            .parse::<usize>()
            .map_err(|_| env::VarError::NotPresent)?;

        Ok(Config {
            ipfs_node: env::var("IPFS_NODE")
                .unwrap_or_else(|_| "http://127.0.0.1:5001".to_string()),
            database_url: env::var("DATABASE_URL")?,
            bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8081".to_string()),
            dilithium_public_key: env::var("DILITHIUM_PUBLIC_KEY")?,
            dilithium_secret_key: env::var("DILITHIUM_SECRET_KEY")?,
            max_concurrent_uploads,
        })
    }

    pub fn get_public_key(&self) -> Result<PublicKey, String> {
        let public_key_bytes = Base64Engine
            .decode(&self.dilithium_public_key)
            .map_err(|e| format!("Failed to decode public key: {}", e))?;
        PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| format!("Invalid Dilithium public key format: {}", e))
    }

    pub fn get_secret_key(&self) -> Result<SecretKey, String> {
        let secret_key_bytes = Base64Engine
            .decode(&self.dilithium_secret_key)
            .map_err(|e| format!("Failed to decode secret key: {}", e))?;
        SecretKey::from_bytes(&secret_key_bytes)
            .map_err(|e| format!("Invalid Dilithium secret key format: {}", e))
    }
}
