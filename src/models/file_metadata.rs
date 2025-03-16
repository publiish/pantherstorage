use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

/// Metadata for files stored in IPFS
///
/// ```rust
/// use chrono::Utc;
/// let metadata = FileMetadata {
///     cid: "Qm...".to_string(),
///     name: "example.txt".to_string(),
///     size: 1024,
///     timestamp: Utc::now(),
///     user_id: 1,
/// };test
/// ```
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct FileMetadata {
    pub cid: String,
    pub name: String,
    pub size: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub timestamp: DateTime<Utc>,
    pub user_id: i32,
}
