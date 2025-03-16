use crate::models::auth::Claims;
use crate::{
    config::Config,
    errors::ServiceError,
    models::{file_metadata::FileMetadata, requests::*},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use futures::stream::StreamExt;
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::info;
use mysql_async::{prelude::*, Opts, Pool};
use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};
use validator::Validate;

// Service handling IPFS operations and user management
pub struct IPFSService {
    pub client: IpfsClient,
    pub db_pool: Pool,
    pub url: String,
    pub jwt_secret: String,
}

impl IPFSService {
    /// Initializes a new IPFS service instance
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use tokio;
    /// # async fn example() {
    /// let config = Config::from_env().unwrap();
    /// let service = IPFSService::new(&config).await.unwrap();
    /// # }
    /// ```
    pub async fn new(config: &Config) -> Result<Self, ServiceError> {
        let client = IpfsClient::from_str(&config.ipfs_node)?;
        let version = client.version().await?;
        info!(
            "Connected to IPFS node: {} (version: {})",
            config.ipfs_node, version.version
        );

        let opts = Opts::from_url(&config.database_url)?;
        let pool = Pool::new(opts);
        let mut conn = pool.get_conn().await?;

        conn.query_drop(
            r"CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                email VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email)
            )",
        )
        .await?;

        conn.query_drop(
            r"CREATE TABLE IF NOT EXISTS file_metadata (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                cid VARCHAR(100) NOT NULL UNIQUE,
                name VARCHAR(255) NOT NULL,
                size BIGINT NOT NULL,
                timestamp DATETIME NOT NULL,
                user_id INT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_cid (cid),
                INDEX idx_user_id (user_id)
            )",
        )
        .await?;

        info!("Database schema initialized");

        Ok(Self {
            client,
            db_pool: pool,
            url: config.ipfs_node.clone(),
            jwt_secret: config.jwt_secret.clone(),
        })
    }

    /// Registers a new user and returns a JWT token
    pub async fn signup(&self, req: SignupRequest) -> Result<String, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;
        let password_hash =
            hash(&req.password, DEFAULT_COST).map_err(|_| ServiceError::Internal)?;
        let mut conn = self.db_pool.get_conn().await?;
        let result = conn
            .exec_drop(
                "INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)",
                params! {
                    "username" => &req.username,
                    "email" => &req.email,
                    "password_hash" => &password_hash,
                },
            )
            .await;

        if let Err(mysql_async::Error::Server(err)) = &result {
            if err.code == 1062 {
                return Err(ServiceError::InvalidInput(
                    "Username or email already exists".to_string(),
                ));
            }
        }
        result?;

        let user_id: i32 = conn
            .query_first("SELECT LAST_INSERT_ID()")
            .await?
            .ok_or(ServiceError::Internal)?;

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + Duration::days(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| ServiceError::Internal)?;

        info!("New user signed up: {}", req.email);
        Ok(token)
    }

    /// Authenticates a user and returns a JWT token
    pub async fn signin(&self, req: SigninRequest) -> Result<String, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;
        let mut conn = self.db_pool.get_conn().await?;
        let user: Option<(i32, String)> = conn
            .exec_first(
                "SELECT id, password_hash FROM users WHERE email = :email",
                params! { "email" => &req.email },
            )
            .await?;

        let (user_id, password_hash) =
            user.ok_or(ServiceError::Auth("Invalid credentials".to_string()))?;

        if !verify(&req.password, &password_hash).map_err(|_| ServiceError::Internal)? {
            return Err(ServiceError::Auth("Invalid credentials".to_string()));
        }

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + Duration::days(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| ServiceError::Internal)?;

        info!("User signed in: {}", req.email);
        Ok(token)
    }

    /// Uploads a file to IPFS and stores its metadata
    pub async fn upload_file(
        &self,
        file_path: &str,
        user_id: i32,
    ) -> Result<FileMetadata, ServiceError> {
        if !Path::new(file_path).exists() {
            return Err(ServiceError::InvalidInput(format!(
                "File not found: {}",
                file_path
            )));
        }

        let mut file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        let file_name = Path::new(file_path)
            .file_name()
            .ok_or(ServiceError::InvalidInput("Invalid file path".to_string()))?
            .to_str()
            .ok_or(ServiceError::InvalidInput("Invalid file name".to_string()))?
            .to_string();

        let mut contents = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut contents)?;
        let cursor = Cursor::new(contents);

        let response = self.client.add(cursor).await?;
        self.client.pin_add(&response.hash, true).await?;

        let metadata = FileMetadata {
            cid: response.hash.clone(),
            name: file_name,
            size: file_size,
            timestamp: Utc::now(),
            user_id,
        };

        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            "INSERT INTO file_metadata (cid, name, size, timestamp, user_id) VALUES (:cid, :name, :size, :timestamp, :user_id)",
            params! {
                "cid" => &metadata.cid,
                "name" => &metadata.name,
                "size" => &metadata.size,
                "timestamp" => metadata.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                "user_id" => user_id,
            },
        ).await?;

        info!("File uploaded by user {}: {}", user_id, metadata.cid);
        Ok(metadata)
    }

    /// Downloads a file from IPFS to the specified path
    pub async fn download_file(
        &self,
        cid: &str,
        output_path: &str,
        user_id: i32,
    ) -> Result<(), ServiceError> {
        let metadata = self
            .get_file_metadata(cid)
            .await?
            .ok_or(ServiceError::InvalidInput("File not found".to_string()))?;

        if metadata.user_id != user_id {
            return Err(ServiceError::Auth(
                "Not authorized to access this file".to_string(),
            ));
        }

        let mut stream = self.client.cat(cid);
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend(chunk?);
        }

        std::fs::write(output_path, &bytes)?;
        info!("File downloaded by user {}: {}", user_id, cid);
        Ok(())
    }

    /// Deletes a file from IPFS and removes its metadata
    pub async fn delete_file(&self, cid: &str, user_id: i32) -> Result<(), ServiceError> {
        let metadata = self
            .get_file_metadata(cid)
            .await?
            .ok_or(ServiceError::InvalidInput("File not found".to_string()))?;

        if metadata.user_id != user_id {
            return Err(ServiceError::Auth(
                "Not authorized to delete this file".to_string(),
            ));
        }

        self.client.pin_rm(cid, true).await?;
        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            "DELETE FROM file_metadata WHERE cid = :cid",
            params! { "cid" => cid },
        )
        .await?;

        info!("File deleted by user {}: {}", user_id, cid);
        Ok(())
    }   

    /// Lists all pinned files for a user
    pub async fn list_pins(&self, user_id: i32) -> Result<Vec<String>, ServiceError> {
        let mut conn = self.db_pool.get_conn().await?;
        let cids: Vec<String> = conn
            .exec_map(
                "SELECT cid FROM file_metadata WHERE user_id = :user_id",
                params! { "user_id" => user_id },
                |cid| cid,
            )
            .await?;

        Ok(cids)
    }

    /// Retrieves metadata for a specific file
    pub async fn get_file_metadata(&self, cid: &str) -> Result<Option<FileMetadata>, ServiceError> {
        let mut conn = self.db_pool.get_conn().await?;
        let result = conn
            .query_first::<mysql_async::Row, _>(format!(
                "SELECT cid, name, size, timestamp, user_id FROM file_metadata WHERE cid = '{}'",
                cid
            ))
            .await?;

        Ok(result.map(|row| FileMetadata {
            cid: row.get("cid").unwrap(),
            name: row.get("name").unwrap(),
            size: row.get("size").unwrap(),
            // Note: Should parse from DB in production
            timestamp: Utc::now(),
            user_id: row.get("user_id").unwrap(),
        }))
    }
}
