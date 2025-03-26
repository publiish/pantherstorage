use crate::stream::SizedByteStream;
use crate::{errors::ServiceError, models::file_metadata::TaskInfo};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use futures::Stream;
use ipfs_api::{IpfsApi, IpfsClient};
use mysql_async::{prelude::*, Pool};
use std::sync::atomic::Ordering;
use std::{collections::HashMap, sync::Arc};
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

/// Cleans up old upload tasks from memory and database that are older than 2 hours
/// and have a status of 'completed' or 'failed'. This should be run periodically.
pub async fn cleanup_old_tasks(
    db_pool: &Pool,
    tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
) -> Result<(), ServiceError> {
    let cutoff_time = Utc::now() - Duration::hours(2);
    log::info!("Starting cleanup of tasks older than {}", cutoff_time);

    // Clean up in-memory tasks
    {
        let mut tasks = tasks.write().await;
        let initial_count = tasks.len();
        tasks.retain(|task_id, info| {
            let keep = info.status.started_at > cutoff_time
                || (info.status.status != "completed" && info.status.status != "failed");
            if !keep {
                log::info!(
                    "Removing in-memory task {} started at {}",
                    task_id,
                    info.status.started_at
                );
            }
            keep
        });
        let removed_count = initial_count - tasks.len();
        log::info!("Removed {} old tasks from in-memory cache", removed_count);
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
        log::info!(
            "Removed {} old tasks from upload_tasks table",
            affected_rows_count
        );
    } else {
        log::info!("No old tasks found in database to remove");
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
