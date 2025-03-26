use log::info;
use mysql_async::{prelude::*, Pool};

/// Initializes the database schema by creating necessary tables if they don't exist
pub async fn init_schema(pool: &Pool) -> Result<(), mysql_async::Error> {
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
    Ok(())
}
