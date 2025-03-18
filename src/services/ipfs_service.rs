use crate::models::auth::Claims;
use crate::{
    config::Config,
    errors::ServiceError,
    models::{file_metadata::FileMetadata, requests::*},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, NaiveDateTime, TimeZone, Utc};
use futures::Stream;
use futures_util::{io::AsyncRead, StreamExt};
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::info;
use mysql_async::{prelude::*, Opts, Pool, Row, Value};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use validator::Validate;

// Service handling IPFS operations and user management
pub struct IPFSService {
    pub client: IpfsClient,
    pub db_pool: Pool,
    pub jwt_secret: String,
    #[allow(dead_code)]
    pub url: String,
}

/// Wraps a byte stream and tracks its total size.
/// This is useful for monitoring the amount of data processed through the stream.
pub struct SizedByteStream<T> {
    // The underlying stream, pinned in memory for safe async operations
    inner: Pin<Box<T>>,
    // Thread-safe counter for total bytes processed
    size: Arc<AtomicU64>,
    // Internal buffer for partial reads
    buffer: Vec<u8>,
    // Current position in the buffer
    buffer_pos: usize,
}

impl<T> SizedByteStream<T>
where
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + 'static,
{
    /// Creates a new SizedByteStream and returns it along with a shared size counter.
    ///
    /// # Arguments
    /// * `inner` - The underlying stream to wrap
    ///
    /// # Returns
    /// A tuple containing the new SizedByteStream and a clone of the size counter
    fn new(inner: T) -> (Self, Arc<AtomicU64>) {
        // Initialize atomic counter at 0
        let size = Arc::new(AtomicU64::new(0));
        (
            Self {
                // Pin the stream in memory for async safety
                inner: Box::pin(inner),
                // Clone the counter for internal use
                size: size.clone(),
                // Initialize empty buffer
                buffer: Vec::new(),
                // Start at buffer position 0
                buffer_pos: 0,
            },
            // Return the shared counter
            size,
        )
    }
}

impl<T> Stream for SizedByteStream<T>
where
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + 'static,
{
    // Stream yields byte vectors or IO errors
    type Item = Result<Vec<u8>, std::io::Error>;

    /// Polls the underlying stream for the next chunk of data.
    /// Updates the size counter when data is received.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Get mutable reference to self
        let this = self.get_mut();

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Successfully received data: update size counter atomically
                this.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                // Return the data
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::Other, e))))
            }
            // Stream has ended
            Poll::Ready(None) => Poll::Ready(None),
            // No data ready yet
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> AsyncRead for SizedByteStream<T>
where
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
{
    /// Attempts to read data into the provided buffer.
    /// Uses internal buffering to handle partial reads efficiently.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        // Destination buffer to read into
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // First, try to consume any remaining data in the internal buffer
        if this.buffer_pos < this.buffer.len() {
            // Get remaining buffer slice
            let remaining = &this.buffer[this.buffer_pos..];
            // Calculate bytes to copy
            let to_copy = std::cmp::min(remaining.len(), buf.len());
            // Copy to output buffer
            buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
            // Update buffer position
            this.buffer_pos += to_copy;
            // Return number of bytes read
            return Poll::Ready(Ok(to_copy));
        }

        // If buffer is empty, poll the underlying stream for more data
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Update size counter with new data
                this.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                // Calculate bytes to copy
                let to_copy = std::cmp::min(bytes.len(), buf.len());

                if to_copy < bytes.len() {
                    // If buffer can't hold all data, store excess in internal buffer
                    // Store full chunk
                    this.buffer = bytes;
                    // Set position after copied data
                    this.buffer_pos = to_copy;
                    // Copy what fits
                    buf[..to_copy].copy_from_slice(&this.buffer[..to_copy]);
                } else {
                    // If buffer can hold all data, copy directly
                    buf[..to_copy].copy_from_slice(&bytes);
                    // Clear internal buffer
                    this.buffer.clear();
                    // Reset position
                    this.buffer_pos = 0;
                }
                Poll::Ready(Ok(to_copy))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl IPFSService {
    /// Initializes a new IPFS service instance
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
        let password_hash = hash(&req.password, DEFAULT_COST)
            .map_err(|e| ServiceError::Internal(format!("Failed to hash password: {}", e)))?;
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
            .ok_or_else(|| ServiceError::Internal("Failed to get user ID".to_string()))?;

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + Duration::days(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| ServiceError::Internal(format!("Failed to generate token: {}", e)))?;

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

        if !verify(&req.password, &password_hash)
            .map_err(|e| ServiceError::Internal(format!("Password verification failed: {}", e)))?
        {
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
        .map_err(|e| ServiceError::Internal(format!("Failed to generate token: {}", e)))?;

        info!("User signed in: {}", req.email);
        Ok(token)
    }

    /// Uploads a file to IPFS and stores its metadata
    pub async fn upload_file<S>(
        &self,
        file_stream: S,
        file_name: String,
        user_id: i32,
    ) -> Result<FileMetadata, ServiceError>
    where
        S: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
    {
        let (sized_stream, size_tracker) = SizedByteStream::new(file_stream);

        let response = self
            .client
            .add_async(sized_stream)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to upload to IPFS: {}", e)))?;

        self.client
            .pin_add(&response.hash, true)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to pin content: {}", e)))?;

        let total_size = size_tracker.load(Ordering::SeqCst);
        if total_size == 0 {
            self.cleanup_failed_upload(&response.hash).await?;
            return Err(ServiceError::InvalidInput(
                "Empty file uploaded".to_string(),
            ));
        }

        let metadata = FileMetadata {
            cid: response.hash.clone(),
            name: file_name.clone(),
            size: total_size,
            timestamp: Utc::now(),
            user_id,
        };

        let mut conn = self.db_pool.get_conn().await?;
        let mut tx = conn
            .start_transaction(mysql_async::TxOpts::default())
            .await?;

        tx.exec_drop(
            "INSERT INTO file_metadata (cid, name, size, timestamp, user_id) VALUES (:cid, :name, :size, :timestamp, :user_id)",
            params! {
                "cid" => &metadata.cid,
                "name" => &metadata.name,
                "size" => metadata.size,
                "timestamp" => metadata.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                "user_id" => user_id,
            },
        ).await?;

        tx.commit().await?;

        info!(
            "File uploaded successfully: cid={}, size={}, user_id={}",
            metadata.cid, metadata.size, user_id
        );

        Ok(metadata)
    }

    async fn cleanup_failed_upload(&self, cid: &str) -> Result<(), ServiceError> {
        self.client
            .pin_rm(cid, true)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to remove pin: {}", e)))?;
        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            "DELETE FROM file_metadata WHERE cid = :cid",
            params! { "cid" => cid },
        )
        .await?;
        Ok(())
    }

    #[allow(dead_code)]
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
            bytes.extend(
                chunk.map_err(|e| ServiceError::Internal(format!("Download failed: {}", e)))?,
            );
        }

        std::fs::write(output_path, &bytes)
            .map_err(|e| ServiceError::Internal(format!("Failed to write file: {}", e)))?;
        info!("File downloaded by user {}: {}", user_id, cid);
        Ok(())
    }

    /// Fetches file bytes from IPFS for direct serving
    pub async fn fetch_file_bytes(&self, cid: &str, user_id: i32) -> Result<Vec<u8>, ServiceError> {
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
            bytes
                .extend(chunk.map_err(|e| ServiceError::Internal(format!("Fetch failed: {}", e)))?);
        }

        info!("File fetched by user {}: {}", user_id, cid);
        Ok(bytes)
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

        self.client
            .pin_rm(cid, true)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to remove pin: {}", e)))?;
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
        let result: Option<Row> = conn
            .exec_first(
                "SELECT cid, name, size, timestamp, user_id FROM file_metadata WHERE cid = :cid",
                params! { "cid" => cid },
            )
            .await?;

        Ok(result.map(|row| {
            // Handle the timestamp value properly
            let timestamp_value: Value = row.get(3).unwrap();
            let timestamp = match timestamp_value {
                Value::Date(year, month, day, hour, minute, second, micro) => NaiveDateTime::new(
                    chrono::NaiveDate::from_ymd_opt(year.into(), month.into(), day.into()).unwrap(),
                    chrono::NaiveTime::from_hms_micro_opt(
                        hour.into(),
                        minute.into(),
                        second.into(),
                        micro,
                    )
                    .unwrap(),
                ),
                _ => {
                    // Fallback to parsing from string if needed
                    let timestamp_str: String = row.get::<String, _>(3).unwrap();
                    NaiveDateTime::parse_from_str(&timestamp_str, "%Y-%m-%d %H:%M:%S")
                        .unwrap_or_else(|_| Utc::now().naive_utc())
                }
            };
            let timestamp_utc = Utc.from_utc_datetime(&timestamp);

            FileMetadata {
                cid: row.get(0).unwrap(),
                name: row.get(1).unwrap(),
                size: row.get(2).unwrap(),
                timestamp: timestamp_utc,
                user_id: row.get(4).unwrap(),
            }
        }))
    }
}
