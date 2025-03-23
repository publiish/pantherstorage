use crate::models::auth::Claims;
use crate::utils::{
    cleanup_failed_upload, hash_password, insert_file_metadata, insert_initial_task,
    update_task_status, upload_to_ipfs, verify_password,
};
use crate::{
    config::Config,
    errors::ServiceError,
    models::{file_metadata::FileMetadata, requests::*},
};
use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};
use futures::Stream;
use futures_util::StreamExt;
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::error;
use log::info;
use mysql_async::{prelude::*, Opts, Pool, Row, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock, Semaphore};
use uuid::Uuid;
use validator::Validate;

/// Service handling IPFS operations and user management
pub struct IPFSService {
    pub client: IpfsClient,
    pub db_pool: Pool,
    pub jwt_secret: String,
    // In-memory task tracking
    pub tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    // Cap concurrent uploads
    operation_semaphore: Arc<Semaphore>,
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
    pub started_at: DateTime<Utc>,
}

/// Task tracking information stored in memory and database
pub struct TaskInfo {
    pub status: UploadStatus,
    pub tx: Option<oneshot::Sender<Result<FileMetadata, ServiceError>>>,
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
            operation_semaphore: Arc::new(Semaphore::new(config.max_concurrent_uploads)),
        })
    }

    /// Registers a new user and returns a JWT token
    pub async fn signup(&self, req: SignupRequest) -> Result<String, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;
        let password_hash = hash_password(&req.password)?;
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

        if !verify_password(&req.password, &password_hash)? {
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
        // Acquire a semaphore permit to limit concurrent uploads
        let _permit =
            self.operation_semaphore.acquire().await.map_err(|e| {
                ServiceError::Internal(format!("Failed to acquire semaphore: {}", e))
            })?;

        let (cid, total_size) = upload_to_ipfs(&self.client, file_stream).await?;

        if total_size == 0 {
            cleanup_failed_upload(&self.client, &self.db_pool, &cid).await?;
            return Err(ServiceError::InvalidInput(
                "Empty file uploaded".to_string(),
            ));
        }

        let metadata = FileMetadata {
            cid: cid.clone(),
            name: file_name.clone(),
            size: total_size,
            timestamp: Utc::now(),
            user_id,
        };

        insert_file_metadata(&self.db_pool, &cid, &file_name, total_size, user_id, None).await?;

        info!(
            "File uploaded successfully: cid={}, size={}, user_id={}",
            metadata.cid, metadata.size, user_id
        );

        Ok(metadata)
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
        insert_initial_task(
            &self.db_pool,
            &task_id,
            user_id,
            // Initial status ("pending")
            &status.status,
            status.started_at,
        )
        .await?;

        // Clone necessary data for async task
        let client = self.client.clone();
        let db_pool = self.db_pool.clone();
        let tasks = self.tasks.clone();
        let semaphore = self.operation_semaphore.clone();
        let task_id_clone = task_id.clone();
        let file_name_clone = file_name.clone();

        tokio::task::spawn_local(async move {
            // Acquire semaphore permit within the async task
            match semaphore.acquire().await {
                Ok(_permit) => {
                    let result = Self::process_upload(
                        client,
                        db_pool.clone(),
                        file_stream,
                        file_name_clone,
                        user_id,
                        task_id_clone.clone(),
                        tasks.clone(),
                    )
                    .await;

                    match result {
                        Ok(metadata) => {
                            update_task_status(
                                tasks,
                                &db_pool,
                                &task_id_clone,
                                "completed",
                                Some(&metadata.cid),
                                None,
                                Some(100.0),
                            )
                            .await
                            .unwrap_or_else(|e| {
                                error!("Failed to update task status: {}", e);
                            });
                        }
                        Err(e) => {
                            update_task_status(
                                tasks,
                                &db_pool,
                                &task_id_clone,
                                "failed",
                                None,
                                Some(&e.to_string()),
                                None,
                            )
                            .await
                            .unwrap_or_else(|e| {
                                error!("Failed to update task status: {}", e);
                            });
                        }
                    }
                }
                Err(e) => {
                    // Handle semaphore acquisition failure
                    update_task_status(
                        tasks,
                        &db_pool,
                        &task_id_clone,
                        "failed",
                        None,
                        Some(&format!("Failed to acquire semaphore: {}", e)),
                        None,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        error!("Failed to update task status: {}", e);
                    });
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
        tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    ) -> Result<FileMetadata, ServiceError>
    where
        S: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
    {
        let (cid, total_size) = upload_to_ipfs(&client, file_stream).await?;

        let metadata = FileMetadata {
            cid: cid.clone(),
            name: file_name.clone(),
            size: total_size,
            timestamp: Utc::now(),
            user_id,
        };

        // Insert metadata into the database with task_id
        insert_file_metadata(
            &db_pool,
            &cid,
            &file_name,
            total_size,
            user_id,
            Some(&task_id),
        )
        .await?;

        // Update task status
        update_task_status(
            tasks.clone(),
            &db_pool,
            &task_id,
            "completed",
            Some(&cid),
            None,
            Some(100.0),
        )
        .await?;

        // Send the result back using the tx field
        if let Some(task_info) = tasks.write().await.get_mut(&task_id) {
            if let Some(tx) = task_info.tx.take() {
                let _ = tx.send(Ok(metadata.clone()));
            }
        }

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
        log::info!("Skipping garbage collection for CID {}", cid);

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
