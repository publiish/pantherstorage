mod schema;
mod users;

pub use schema::init_schema;
pub use users::{login_user, register_user};

use crate::models::file_metadata::{TaskInfo, UploadStatus};
use crate::{errors::ServiceError, IPFSService};
use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};
use dashmap::DashMap;
use ipfs_api::{IpfsApi, IpfsClient};
use log::info;
use mysql_async::{prelude::*, Pool, Row};
use std::sync::Arc;

/// Inserts file metadata into the database.
pub async fn insert_file_metadata(
    db_pool: &Pool,
    cid: &str,
    name: &str,
    size: u64,
    user_id: i32,
    task_id: Option<&str>,
) -> Result<(), ServiceError> {
    let mut conn = db_pool
        .get_conn()
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get DB connection: {}", e)))?;
    let mut tx = conn
        .start_transaction(mysql_async::TxOpts::default())
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to start transaction: {}", e)))?;

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
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to insert file metadata: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to commit transaction: {}", e)))?;
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
    let mut conn = db_pool
        .get_conn()
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get DB connection: {}", e)))?;
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
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to insert initial task: {}", e)))?;
    Ok(())
}

/// Updates the status of a task in both the in-memory cache and the database.
pub async fn update_task_status(
    tasks: Arc<DashMap<String, TaskInfo>>,
    db_pool: &Pool,
    task_id: &str,
    status: &str,
    cid: Option<&str>,
    error: Option<&str>,
    progress: Option<f64>,
) -> Result<(), ServiceError> {
    // Update in-memory cache
    if let Some(mut task_info) = tasks.get_mut(task_id) {
        task_info.status.status = status.to_string();
        task_info.status.cid = cid.map(String::from);
        task_info.status.error = error.map(String::from);
        task_info.status.progress = progress;
    } else {
        log::warn!("Task {} not found in cache during status update", task_id);
    }

    // Update database
    let mut conn = db_pool
        .get_conn()
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get DB connection: {}", e)))?;
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
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to update task status: {}", e)))?;

    Ok(())
}

/// Retrieves the upload status, checking the cache first and falling back to the database.
pub async fn get_upload_status(
    service: &IPFSService,
    task_id: &str,
    user_id: i32,
) -> Result<UploadStatus, ServiceError> {
    // Check in-memory cache
    if let Some(task_info) = service.tasks.get(task_id) {
        if task_info.status.started_at.timestamp() > (Utc::now().timestamp() - 3600) {
            return Ok(task_info.status.clone());
        }
    }

    // Query database if not in cache or expired
    let mut conn = service
        .db_pool
        .get_conn()
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get DB connection: {}", e)))?;
    let result: Option<Row> = conn
        .exec_first(
            r"SELECT status, cid, error, progress, started_at, user_id 
              FROM upload_tasks 
              WHERE task_id = :task_id",
            params! { "task_id" => task_id },
        )
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to query upload status: {}", e)))?;

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
                .unwrap_or_else(|e| {
                    log::warn!("Failed to parse started_at: {}, defaulting to now", e);
                    Utc::now()
                });

            let status = UploadStatus {
                task_id: task_id.to_string(),
                status: row.get(0).unwrap(),
                cid: row.get(1),
                error: row.get(2),
                progress: row.get(3),
                started_at,
            };

            // Update cache
            service.tasks.insert(
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

/// Cleans up a failed upload by removing the pin from IPFS and deleting metadata from the database.
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
    let mut conn = db_pool
        .get_conn()
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get DB connection: {}", e)))?;
    conn.exec_drop(
        "DELETE FROM file_metadata WHERE cid = :cid",
        params! { "cid" => cid },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to delete metadata: {}", e)))?;

    log::info!("Cleaned up failed upload for CID: {}", cid);
    Ok(())
}

/// Periodically cleans up expired tasks from the in-memory cache.
/// Removes tasks older than 1 hour that are in a terminal state ("completed" or "failed").
pub async fn cleanup_expired_tasks(
    tasks: Arc<DashMap<String, TaskInfo>>,
) -> Result<(), ServiceError> {
    let cutoff_time = Utc::now() - Duration::hours(1);
    info!(
        "Starting cleanup of expired tasks older than {}",
        cutoff_time
    );

    let initial_count = tasks.len();
    tasks.retain(|task_id, task| {
        let retain = task.status.started_at > cutoff_time
            || (task.status.status != "completed" && task.status.status != "failed");
        if !retain {
            info!(
                "Removed expired task from cache: {} (started at {})",
                task_id, task.status.started_at
            );
        }
        retain
    });

    let removed_count = initial_count - tasks.len();
    if removed_count > 0 {
        info!(
            "Removed {} expired tasks from in-memory cache",
            removed_count
        );
    }

    Ok(())
}
