use crate::errors::ServiceError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio::sync::oneshot;

/// Metadata for files stored in IPFS
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub cid: String,
    pub name: String,
    pub size: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub timestamp: DateTime<Utc>,
    pub user_id: i32,
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
