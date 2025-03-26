mod schema;
mod users;

pub use schema::init_schema;
pub use users::{login_user, register_user};

use crate::models::file_metadata::{TaskInfo, UploadStatus};
use crate::{errors::ServiceError, IPFSService};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use ipfs_api::{IpfsApi, IpfsClient};
use mysql_async::{prelude::*, Pool, Row};
use std::collections::HashMap;

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

pub async fn get_upload_status(
    service: &IPFSService,
    task_id: &str,
    user_id: i32,
) -> Result<UploadStatus, ServiceError> {
    {
        let tasks = service.tasks.read().await;
        if let Some(task_info) = tasks.get(task_id) {
            if task_info.status.started_at.timestamp() > (Utc::now().timestamp() - 3600) {
                return Ok(task_info.status.clone());
            }
        }
    }

    let mut conn = service.db_pool.get_conn().await?;
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

            let mut tasks = service.tasks.write().await;
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
