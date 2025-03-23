use crate::stream::SizedByteStream;
use crate::{errors::ServiceError, services::ipfs_service::TaskInfo};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use futures::Stream;
use ipfs_api::{IpfsApi, IpfsClient};
use log::info;
use mysql_async::{prelude::*, Pool};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Uploads a file to IPFS and returns the CID and file size.
pub async fn upload_to_ipfs<S>(
    client: &IpfsClient,
    file_stream: S,
) -> Result<(String, u64), ServiceError>
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

    Ok((response.hash, total_size))
}

/// Inserts file metadata into the database.
pub async fn insert_file_metadata(
    db_pool: &Pool,
    cid: &str,
    name: &str,
    size: u64,
    user_id: i32,
    task_id: Option<&str>,
) -> Result<(), ServiceError> {
    let mut conn = db_pool.get_conn().await?;
    let mut tx = conn
        .start_transaction(mysql_async::TxOpts::default())
        .await?;

    tx.exec_drop(
        r"INSERT INTO file_metadata (cid, name, size, timestamp, user_id, task_id)
          VALUES (:cid, :name, :size, :timestamp, :user_id, :task_id)",
        params! {
            "cid" => cid,
            "name" => name,
            "size" => size,
            "timestamp" => Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            "user_id" => user_id,
            "task_id" => task_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Inserts an initial task into the upload_tasks table.
pub async fn insert_initial_task(
    db_pool: &Pool,
    task_id: &str,
    user_id: i32,
    status: &str,
    started_at: DateTime<Utc>,
) -> Result<(), ServiceError> {
    let mut conn = db_pool.get_conn().await?;
    conn.exec_drop(
        r"INSERT INTO upload_tasks (task_id, user_id, status, started_at)
          VALUES (:task_id, :user_id, :status, :started_at)",
        params! {
            "task_id" => task_id,
            "user_id" => user_id,
            "status" => status,
            "started_at" => started_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        },
    )
    .await?;
    Ok(())
}

/// Updates the status of a task in both the in-memory cache and the database.
pub async fn update_task_status(
    tasks: std::sync::Arc<tokio::sync::RwLock<HashMap<String, TaskInfo>>>,
    db_pool: &Pool,
    task_id: &str,
    status: &str,
    cid: Option<&str>,
    error: Option<&str>,
    progress: Option<f64>,
) -> Result<(), ServiceError> {
    // Update in-memory cache
    {
        let mut tasks = tasks.write().await;
        if let Some(task_info) = tasks.get_mut(task_id) {
            task_info.status.status = status.to_string();
            task_info.status.cid = cid.map(|s| s.to_string());
            task_info.status.error = error.map(|s| s.to_string());
            task_info.status.progress = progress;
        }
    }

    // Update database
    let mut conn = db_pool.get_conn().await?;
    conn.exec_drop(
        r"UPDATE upload_tasks 
          SET status = :status, cid = :cid, error = :error, progress = :progress, completed_at = NOW()
          WHERE task_id = :task_id",
        params! {
            "task_id" => task_id,
            "status" => status,
            "cid" => cid,
            "error" => error,
            "progress" => progress,
        },
    )
    .await?;

    Ok(())
}

pub async fn cleanup_failed_upload(
    client: &IpfsClient,
    db_pool: &Pool,
    cid: &str,
) -> Result<(), ServiceError> {
    // Remove the pinned file from IPFS
    client
        .pin_rm(cid, true)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to remove pin: {}", e)))?;

    // Delete the metadata from the database
    let mut conn = db_pool.get_conn().await?;
    conn.exec_drop(
        "DELETE FROM file_metadata WHERE cid = :cid",
        params! { "cid" => cid },
    )
    .await?;

    Ok(())
}

/// Cleans up old upload tasks from memory and database that are older than 2 hours
/// and have a status of 'completed' or 'failed'. This should be run periodically.
pub async fn cleanup_old_tasks(
    db_pool: &Pool,
    tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
) -> Result<(), ServiceError> {
    let cutoff_time = Utc::now() - Duration::hours(2);
    info!("Starting cleanup of tasks older than {}", cutoff_time);

    // Clean up in-memory tasks
    {
        let mut tasks = tasks.write().await;
        let initial_count = tasks.len();
        tasks.retain(|task_id, info| {
            let keep = info.status.started_at > cutoff_time
                || (info.status.status != "completed" && info.status.status != "failed");
            if !keep {
                info!(
                    "Removing in-memory task {} started at {}",
                    task_id, info.status.started_at
                );
            }
            keep
        });
        let removed_count = initial_count - tasks.len();
        info!("Removed {} old tasks from in-memory cache", removed_count);
    }

    // Clean up database tasks
    let mut conn = db_pool
        .get_conn()
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get database connection: {}", e)))?;

    let cutoff_str = cutoff_time.format("%Y-%m-%d %H:%M:%S").to_string();
    let _affected_rows = conn
        .exec_drop(
            r"DELETE FROM upload_tasks 
              WHERE started_at < :cutoff 
              AND status IN ('completed', 'failed')",
            params! { "cutoff" => &cutoff_str },
        )
        .await
        .map_err(|e| {
            ServiceError::Internal(format!("Failed to delete old tasks from database: {}", e))
        })?;

    let affected_rows_count = conn.affected_rows();
    if affected_rows_count > 0 {
        info!(
            "Removed {} old tasks from upload_tasks table",
            affected_rows_count
        );
    } else {
        info!("No old tasks found in database to remove");
    }

    Ok(())
}

/// Hashes a password using bcrypt.
pub fn hash_password(password: &str) -> Result<String, ServiceError> {
    hash(password, DEFAULT_COST)
        .map_err(|e| ServiceError::Internal(format!("Failed to hash password: {}", e)))
}

/// Verifies a password against a hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ServiceError> {
    verify(password, hash)
        .map_err(|e| ServiceError::Internal(format!("Password verification failed: {}", e)))
}
