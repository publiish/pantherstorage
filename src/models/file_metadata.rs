use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

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
