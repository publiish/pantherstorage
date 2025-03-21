use crate::models::auth::Claims;
use crate::{
    config::Config,
    errors::ServiceError,
    models::{file_metadata::FileMetadata, requests::*},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, NaiveDateTime, TimeZone, Utc};
use futures::Stream;
use futures_util::StreamExt;
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::info;
use mysql_async::{prelude::*, Opts, Pool, Row, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use tokio::sync::RwLock;
use uuid::Uuid;
use validator::Validate;

/// Service handling IPFS operations and user management
pub struct IPFSService {
    pub client: IpfsClient,
    pub db_pool: Pool,
    pub jwt_secret: String,
    // In-memory task tracking
    tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    #[allow(dead_code)]
    pub url: String,
}

/// Upload status response
#[derive(Serialize, Deserialize, Clone)]
pub struct UploadStatus {
    pub task_id: String,
    // "pending", "completed", "failed"
    pub status: String,
    pub cid: Option<String>,
    pub error: Option<String>,
    // Percentage complete (0.0 to 100.0)
    pub progress: Option<f64>,
    pub started_at: chrono::DateTime<Utc>,
}

/// Task tracking information stored in memory and database
struct TaskInfo {
    status: UploadStatus,
    tx: Option<oneshot::Sender<Result<FileMetadata, ServiceError>>>,
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
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
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
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
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

/// tokio::io::AsyncRead
/// Note: If we later need to read from a Tokio based source (e.g., tokio::fs::File
/// or a network stream), SizedByteStream can be used without additional wrappers
impl<T> tokio::io::AsyncRead for SizedByteStream<T>
where
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
{
    /// Attempts to read data into the provided buffer.
    /// Uses internal buffering to handle partial reads efficiently.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        // Destination buffer to read into
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // First, try to consume any remaining data in the internal buffer
        if this.buffer_pos < this.buffer.len() {
            // Get remaining buffer slice
            let remaining = &this.buffer[this.buffer_pos..];
            // Calculate bytes to copy
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            // Copy to output buffer
            buf.put_slice(&remaining[..to_copy]);
            // Update buffer position
            this.buffer_pos += to_copy;
            // Return number of bytes read
            return Poll::Ready(Ok(()));
        }

        // If buffer is empty, poll the underlying stream for more data
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Update size counter with new data
                this.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                // Calculate bytes to copy
                let to_copy = std::cmp::min(bytes.len(), buf.remaining());

                if to_copy < bytes.len() {
                    // If buffer can't hold all data, store excess in internal buffer
                    // Store full chunk
                    this.buffer = bytes;
                    // Set position after copied data
                    this.buffer_pos = to_copy;
                    // Copy what fits
                    buf.put_slice(&this.buffer[..to_copy]);
                } else {
                    // If buffer can hold all data, copy directly
                    buf.put_slice(&bytes);
                    // Clear internal buffer
                    this.buffer.clear();
                    // Reset position
                    this.buffer_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// futures_util::AsyncRead
/// Implements futures_util::AsyncRead for SizedByteStream, enabling asynchronous byte reading.
/// This is a key component for streaming data to IPFS in a non-blocking manner.
impl<T> futures_util::AsyncRead for SizedByteStream<T>
where
    // The 'static lifetime ensures the stream lives long enough for async operations.
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
{
    /// Polls the stream to read data into the provided buffer, leveraging internal buffering.
    /// This method is critical for efficient async I/O in the IPFSService upload pipeline.
    /// It balances memory usage with performance by buffering excess data when the input chunk
    /// exceeds the output buffer size. The atomic size tracking (via `size`) supports monitoring
    /// upload progress, which ties into the UploadStatus feature.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        // Destination buffer to read into
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Check for buffered data first - avoids unnecessary polling of the inner stream.
        // This optimization reduces latency for partial reads, which is common
        // when IPFS processes data in chunks larger than the caller's buffer.
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

        // Poll the inner stream when the buffer is exhausted.
        // The match block handles all stream states cleanly, ensuring proper error
        // propagation and EOF signaling. The use of SeqCst for size updates is conservative but
        // guarantees correctness in multi-threaded contexts, though Relaxed might suffice here
        // since async tasks are typically single-threaded per stream.
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Update size counter with new data
                this.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                // Calculate bytes to copy
                let to_copy = std::cmp::min(bytes.len(), buf.len());

                // Handle oversized chunks by buffering the excess.
                // This branching logic is a pragmatic trade-off: it avoids reallocating
                // the output buffer while preserving unread data for the next poll. However, it
                // assumes the caller will eventually consume all data, or the buffer could grow
                // unbounded with a misbehaving client, we should consider adding a max buffer size check
                // in a production setting.
                if to_copy < bytes.len() {
                    this.buffer = bytes;
                    this.buffer_pos = to_copy;
                    buf[..to_copy].copy_from_slice(&this.buffer[..to_copy]);
                } else {
                    buf[..to_copy].copy_from_slice(&bytes);
                    this.buffer.clear();
                    this.buffer_pos = 0;
                }
                Poll::Ready(Ok(to_copy))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            // EOF: Signal end of stream with 0 bytes read.
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            // Pending: No data yet, rely on the waker for retry.
            // Note: Proper Pending handling is essential for non-blocking behavior,
            // integrating well with tokio’s event loop in the broader async upload system.
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
                task_id VARCHAR(36),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_cid (cid),
                INDEX idx_user_id (user_id),
                INDEX idx_task_id (task_id)
            )",
        )
        .await?;

        conn.query_drop(
            r"CREATE TABLE IF NOT EXISTS upload_tasks (
                task_id VARCHAR(36) PRIMARY KEY,
                user_id INT NOT NULL,
                status VARCHAR(20) NOT NULL,
                cid VARCHAR(100),
                error TEXT,
                progress DOUBLE DEFAULT 0.0,
                started_at DATETIME NOT NULL,
                completed_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
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
            tasks: Arc::new(RwLock::new(HashMap::new())),
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

    /// Performs file upload synchronously and stores its metadata
    pub async fn upload<S>(
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

    /// Return a pending status and task ID immediately and processes the upload
    /// asynchronously in the background allowing status checking later.
    pub async fn upload_file<S>(
        &self,
        file_stream: S,
        file_name: String,
        user_id: i32,
    ) -> Result<UploadStatus, ServiceError>
    where
        S: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
    {
        // Generate unique task ID using UUID
        let task_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();

        // Initial status
        let status = UploadStatus {
            task_id: task_id.clone(),
            status: "pending".to_string(),
            cid: None,
            error: None,
            progress: Some(0.0),
            started_at,
        };

        // Create oneshot channel for result communication
        let (tx, _rx) = oneshot::channel();

        // Store task info
        {
            let mut tasks = self.tasks.write().await;
            tasks.insert(
                task_id.clone(),
                TaskInfo {
                    status: status.clone(),
                    tx: Some(tx),
                },
            );
        }

        // Store initial task in database
        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            r"INSERT INTO upload_tasks (task_id, user_id, status, started_at)
              VALUES (:task_id, :user_id, :status, :started_at)",
            params! {
                "task_id" => &task_id,
                "user_id" => user_id,
                "status" => &status.status,
                "started_at" => status.started_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            },
        )
        .await?;

        // Clone necessary data for async task
        let client = self.client.clone();
        let db_pool = self.db_pool.clone();
        let tasks = self.tasks.clone();
        let task_id_clone = task_id.clone();
        let file_name_clone = file_name.clone();

        tokio::task::spawn_local(async move {
            let result = Self::process_upload(
                client,
                db_pool,
                file_stream,
                file_name_clone,
                user_id,
                task_id_clone.clone(),
                tasks.clone(),
            )
            .await;

            // Update task status
            let mut tasks = tasks.write().await;
            if let Some(task_info) = tasks.get_mut(&task_id_clone) {
                match &result {
                    Ok(metadata) => {
                        task_info.status.status = "completed".to_string();
                        task_info.status.cid = Some(metadata.cid.clone());
                        task_info.status.progress = Some(100.0);
                    }
                    Err(e) => {
                        task_info.status.status = "failed".to_string();
                        task_info.status.error = Some(e.to_string());
                    }
                }
                if let Some(tx) = task_info.tx.take() {
                    let _ = tx.send(result);
                }
            }
        });

        Ok(status)
    }

    async fn process_upload<S>(
        client: IpfsClient,
        db_pool: Pool,
        file_stream: S,
        file_name: String,
        user_id: i32,
        task_id: String,
        _tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    ) -> Result<FileMetadata, ServiceError>
    where
        S: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
    {
        let (sized_stream, size_tracker) = SizedByteStream::new(file_stream);

        let response = client
            .add_async(sized_stream)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to upload to IPFS: {}", e)))?;

        client
            .pin_add(&response.hash, true)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to pin content: {}", e)))?;

        client
            .pin_rm(&response.hash, true)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to remove pin: {}", e)))?;

        let total_size = size_tracker.load(Ordering::SeqCst);
        if total_size == 0 {
            client
                .pin_rm(&response.hash, true)
                .await
                .map_err(|e| ServiceError::Internal(format!("Failed to remove pin: {}", e)))?;
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

        let mut conn = db_pool.get_conn().await?;
        let mut tx = conn
            .start_transaction(mysql_async::TxOpts::default())
            .await?;

        // Update file metadata with task_id
        tx.exec_drop(
            r"INSERT INTO file_metadata (cid, name, size, timestamp, user_id, task_id)
              VALUES (:cid, :name, :size, :timestamp, :user_id, :task_id)",
            params! {
                "cid" => &metadata.cid,
                "name" => &metadata.name,
                "size" => metadata.size,
                "timestamp" => metadata.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                "user_id" => user_id,
                "task_id" => &task_id,
            },
        )
        .await?;

        // Update task status
        tx.exec_drop(
            r"UPDATE upload_tasks 
              SET status = 'completed', cid = :cid, progress = 100.0, completed_at = NOW()
              WHERE task_id = :task_id",
            params! {
                "task_id" => &task_id,
                "cid" => &metadata.cid,
            },
        )
        .await?;

        tx.commit().await?;

        info!(
            "File uploaded successfully: cid={}, size={}, user_id={}, task_id={}",
            metadata.cid, metadata.size, user_id, task_id
        );

        Ok(metadata)
    }

    // First check in-memory cache
    pub async fn get_upload_status(
        &self,
        task_id: &str,
        user_id: i32,
    ) -> Result<UploadStatus, ServiceError> {
        {
            let tasks = self.tasks.read().await;
            if let Some(task_info) = tasks.get(task_id) {
                // 1 hour cache
                if task_info.status.started_at.timestamp() > (Utc::now().timestamp() - 3600) {
                    return Ok(task_info.status.clone());
                }
            }
        }

        // Fall back to database
        let mut conn = self.db_pool.get_conn().await?;
        let result: Option<Row> = conn
            .exec_first(
                r"SELECT status, cid, error, progress, started_at, user_id 
                  FROM upload_tasks 
                  WHERE task_id = :task_id",
                params! { "task_id" => task_id },
            )
            .await?;

        match result {
            Some(row) => {
                let db_user_id: i32 = row.get(5).unwrap();
                if db_user_id != user_id {
                    return Err(ServiceError::Auth(
                        "Not authorized to view this task".to_string(),
                    ));
                }

                let started_at: String = row.get(4).unwrap();
                let started_at = NaiveDateTime::parse_from_str(&started_at, "%Y-%m-%d %H:%M:%S")
                    .map(|ndt| Utc.from_utc_datetime(&ndt))
                    .unwrap_or_else(|_| Utc::now());

                let status = UploadStatus {
                    task_id: task_id.to_string(),
                    status: row.get(0).unwrap(),
                    cid: row.get(1),
                    error: row.get(2),
                    progress: row.get(3),
                    started_at,
                };

                let mut tasks = self.tasks.write().await;
                tasks.insert(
                    task_id.to_string(),
                    TaskInfo {
                        status: status.clone(),
                        tx: None,
                    },
                );

                Ok(status)
            }
            None => Err(ServiceError::InvalidInput("Task not found".to_string())),
        }
    }

    // @TODO: Cleanup old tasks (could be run periodically)
    #[allow(dead_code)]
    pub async fn cleanup_old_tasks(&self) -> Result<(), ServiceError> {
        let mut tasks = self.tasks.write().await;
        tasks.retain(|_, info| {
            // Let's keep 24 hours for now
            info.status.started_at.timestamp() > (Utc::now().timestamp() - 24 * 3600)
        });

        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            r"DELETE FROM upload_tasks 
              WHERE started_at < DATE_SUB(NOW(), INTERVAL 24 HOUR) 
              AND status IN ('completed', 'failed')",
            (),
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
        let metadata = self.get_file_metadata(cid).await?.ok_or_else(|| {
            ServiceError::InvalidInput(format!("File with CID {} not found", cid))
        })?;

        if metadata.user_id != user_id {
            return Err(ServiceError::Auth(
                "Not authorized to delete this file".to_string(),
            ));
        }

        let mut conn = self.db_pool.get_conn().await?;
        let mut tx = conn
            .start_transaction(mysql_async::TxOpts::default())
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to start transaction: {}", e)))?;

        tx.exec_drop(
            "DELETE FROM file_metadata WHERE cid = :cid AND user_id = :user_id",
            params! { "cid" => cid, "user_id" => user_id },
        )
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to delete metadata: {}", e)))?;

        let affected_rows = tx.affected_rows();

        if affected_rows == 0 {
            return Err(ServiceError::Internal(
                "Failed to delete metadata: no rows affected".to_string(),
            ));
        }

        match self.client.pin_rm(cid, true).await {
            Ok(_) => {
                info!("Successfully unpinned CID {} for user {}", cid, user_id);
            }
            Err(e) => {
                // Handle the "not pinned" error gracefully
                if e.to_string().contains("not pinned or pinned indirectly") {
                    info!(
                        "CID {} was not pinned or pinned indirectly; proceeding with deletion for user {}",
                        cid, user_id
                    );
                } else {
                    tx.rollback().await.map_err(|e| {
                        ServiceError::Internal(format!("Failed to rollback transaction: {}", e))
                    })?;
                    return Err(ServiceError::Internal(format!(
                        "Failed to remove pin for CID {}: {}",
                        cid, e
                    )));
                }
            }
        }

        tx.commit()
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to commit transaction: {}", e)))?;

        info!("File deleted successfully by user {}: CID {}", user_id, cid);

        // Note: Garbage collection (`repo_gc`) is not directly supported by `ipfs_api`.
        // If needed, we need to implement a custom HTTP call to the IPFS API endpoint `/repo/gc`.
        log::info!(
            "Skipping garbage collection for CID {}",
            cid
        );

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
