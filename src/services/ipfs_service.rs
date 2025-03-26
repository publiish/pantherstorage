use crate::{
    config::Config,
    database::{
        cleanup_failed_upload, init_schema, insert_file_metadata, insert_initial_task, login_user,
        register_user, update_task_status,
    },
    errors::ServiceError,
    models::{
        auth::{Claims, TokenHeader},
        file_metadata::*,
        requests::*,
    },
    utils::upload_to_ipfs,
};
use chrono::{Duration, NaiveDateTime, TimeZone, Utc};
use futures::Stream;
use futures_util::StreamExt;
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use log::{error, info};
use mysql_async::{prelude::*, Opts, Pool, Row, Value};
use pqcrypto_dilithium::dilithium5::{self, PublicKey, SecretKey};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as OtherPublicKey,
    SecretKey as OtherSecretKey,
};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{oneshot, RwLock, Semaphore};
use uuid::Uuid;

use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;

/// Service handling IPFS operations and user management
pub struct IPFSService {
    pub client: IpfsClient,
    pub db_pool: Pool,
    // Dilithium private key
    signing_key: SecretKey,
    // Dilithium public key
    pub public_key: PublicKey,
    // In-memory task tracking
    pub tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    // Cap concurrent uploads
    operation_semaphore: Arc<Semaphore>,
    #[allow(dead_code)]
    pub url: String,
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

        // Initialize database schema
        init_schema(&pool).await?;

        let public_key = config
            .get_public_key()
            .map_err(|e| ServiceError::Internal(e))?;
        let signing_key = config
            .get_secret_key()
            .map_err(|e| ServiceError::Internal(e))?;

        // Get the bytes for logging
        let public_key_bytes = public_key.as_bytes();
        let secret_key_bytes = signing_key.as_bytes();

        // Log the Public keys as Base64 strings
        info!(
            "Public Key (Base64): {}",
            Base64Engine.encode(&public_key_bytes)
        );
        // Log the SecretKey (! in Production)
        info!(
            "Secret Key (Base64): {}",
            Base64Engine.encode(&secret_key_bytes)
        );

        Ok(Self {
            client,
            db_pool: pool,
            url: config.ipfs_node.clone(),
            signing_key,
            public_key,
            tasks: Arc::new(RwLock::new(HashMap::new())),
            operation_semaphore: Arc::new(Semaphore::new(config.max_concurrent_uploads)),
        })
    }

    /// Generates a PQC authentication token for a given user ID
    fn generate_token(&self, user_id: i32, duration: Duration) -> Result<String, ServiceError> {
        let header = TokenHeader {
            alg: "Dilithium5".to_string(),
            typ: "PQC".to_string(),
            nonce: Uuid::new_v4().to_string(),
        };

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + duration).timestamp() as usize,
            signature: Vec::new(),
            iat: Utc::now().timestamp() as usize,
            nonce: Uuid::new_v4().to_string(),
        };

        let header_json = serde_json::to_string(&header)?;
        let payload_json = serde_json::to_string(&claims)?;
        let header_encoded = Base64Engine.encode(header_json);
        let payload_encoded = Base64Engine.encode(payload_json);

        let message = format!("{}.{}", header_encoded, payload_encoded);
        let signature = dilithium5::detached_sign(message.as_bytes(), &self.signing_key);

        let signature_hash = Sha256::digest(signature.as_bytes());
        let signature_encoded = Base64Engine.encode(&signature_hash);

        Ok(format!(
            "{}.{}.{}",
            header_encoded, payload_encoded, signature_encoded
        ))
    }

    /// Registers a new user and returns a PQC Auth token
    pub async fn signup(&self, req: SignupRequest) -> Result<String, ServiceError> {
        let user_id = register_user(&self.db_pool, &req).await?;
        let token = self.generate_token(user_id, Duration::hours(12))?;
        Ok(token)
    }

    /// Authenticates a user and returns a PQC Auth token
    pub async fn signin(&self, req: SigninRequest) -> Result<String, ServiceError> {
        let user_id = login_user(&self.db_pool, &req).await?;
        let token = self.generate_token(user_id, Duration::hours(12))?;
        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, ServiceError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(ServiceError::Auth("Invalid token format".to_string()));
        }

        let header_encoded = parts[0];
        let payload_encoded = parts[1];
        let signature_encoded = parts[2];

        let header_json = Base64Engine.decode(header_encoded)?;
        let header: TokenHeader = serde_json::from_slice(&header_json)?;
        if header.alg != "Dilithium5" || header.typ != "PQC" {
            return Err(ServiceError::Auth(
                "Unsupported algorithm or type".to_string(),
            ));
        }

        let payload_json = Base64Engine.decode(payload_encoded)?;
        let mut claims: Claims = serde_json::from_slice(&payload_json)?;

        let provided_signature_hash = Base64Engine.decode(signature_encoded)?;
        if provided_signature_hash.len() != 32 {
            return Err(ServiceError::Auth("Invalid signature length".to_string()));
        }

        let message = format!("{}.{}", header_encoded, payload_encoded);
        let signature = dilithium5::detached_sign(message.as_bytes(), &self.signing_key);

        if dilithium5::verify_detached_signature(&signature, message.as_bytes(), &self.public_key)
            .is_err()
        {
            return Err(ServiceError::Auth(
                "Signature verification failed".to_string(),
            ));
        }

        let computed_signature_hash = Sha256::digest(signature.as_bytes());
        if provided_signature_hash != computed_signature_hash.as_slice() {
            return Err(ServiceError::Auth("Invalid signature hash".to_string()));
        }

        if claims.exp < Utc::now().timestamp() as usize {
            return Err(ServiceError::Auth("Token expired".to_string()));
        }

        claims.signature = Vec::new();
        Ok(claims)
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
