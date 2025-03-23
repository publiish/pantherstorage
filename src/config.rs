use std::env;

/// Configuration settings
pub struct Config {
    pub ipfs_node: String,
    pub database_url: String,
    pub bind_address: String,
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
            max_concurrent_uploads,
        })
    }
}
