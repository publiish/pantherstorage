use actix_web::{error::Error as ActixError, web, App, HttpResponse, HttpServer};
use chrono::{DateTime, Utc};
use dotenv::dotenv;
use env_logger::Env;
use futures::stream::StreamExt;
use hyper::http::uri::InvalidUri;
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use log::{debug, error, info, warn};
use mysql_async::{prelude::*, Opts, Pool};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    env,
    fs::File,
    io::{Cursor, Read},
    path::Path,
    sync::Arc,
};
use thiserror::Error;

#[derive(Debug, Error)]
enum ServiceError {
    #[error("Database error: {0}")]
    Database(#[from] mysql_async::Error),
    #[error("IPFS error: {0}")]
    Ipfs(#[from] ipfs_api::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid URI: {0}")]
    InvalidUri(#[from] InvalidUri),
    #[error("URL parsing error: {0}")]
    UrlError(#[from] mysql_async::UrlError),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Internal server error")]
    Internal,
}

impl actix_web::error::ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServiceError::InvalidInput(msg) => HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid input".to_string(),
                message: msg.to_string(),
            }),
            ServiceError::Database(_)
            | ServiceError::Ipfs(_)
            | ServiceError::InvalidUri(_)
            | ServiceError::UrlError(_) => {
                error!("Service error: {}", self);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Service unavailable".to_string(),
                    message: "Something went wrong".to_string(),
                })
            }
            ServiceError::Io(_) | ServiceError::Internal => {
                error!("Internal error: {}", self);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    message: "An unexpected error occurred".to_string(),
                })
            }
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
struct FileMetadata {
    cid: String,
    name: String,
    size: u64,
    #[serde_as(as = "DisplayFromStr")]
    timestamp: DateTime<Utc>,
}

#[derive(Deserialize)]
struct UploadRequest {
    file_path: String,
}

#[derive(Deserialize)]
struct DownloadRequest {
    cid: String,
    output_path: String,
}

#[derive(Deserialize)]
struct DeleteRequest {
    cid: String,
}

struct Config {
    ipfs_node: String,
    database_url: String,
    bind_address: String,
}

impl Config {
    fn from_env() -> Result<Self, env::VarError> {
        dotenv().ok();
        Ok(Config {
            ipfs_node: env::var("IPFS_NODE")
                .unwrap_or_else(|_| "http://127.0.0.1:5001".to_string()),
            database_url: env::var("DATABASE_URL")?,
            bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8081".to_string()),
        })
    }
}

struct IPFSService {
    client: IpfsClient,
    db_pool: Pool,
}

impl IPFSService {
    async fn new(config: &Config) -> Result<Self, ServiceError> {
        let client = IpfsClient::from_str(&config.ipfs_node)?;
        info!("Connected to IPFS node: {}", config.ipfs_node);

        let opts = Opts::from_url(&config.database_url)?;
        let pool = Pool::new(opts);
        let mut conn = pool.get_conn().await?;

        conn.query_drop(
            r"CREATE TABLE IF NOT EXISTS file_metadata (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                cid VARCHAR(100) NOT NULL UNIQUE,
                name VARCHAR(255) NOT NULL,
                size BIGINT NOT NULL,
                timestamp DATETIME NOT NULL,
                INDEX idx_cid (cid)
            )",
        )
        .await?;
        info!("Database schema initialized");

        Ok(Self {
            client,
            db_pool: pool,
        })
    }

    async fn upload_file(&self, file_path: &str) -> Result<FileMetadata, ServiceError> {
        if !Path::new(file_path).exists() {
            return Err(ServiceError::InvalidInput(format!(
                "File not found: {}",
                file_path
            )));
        }

        let mut file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        let file_name = Path::new(file_path)
            .file_name()
            .ok_or_else(|| ServiceError::InvalidInput("Invalid file path".to_string()))?
            .to_str()
            .ok_or_else(|| ServiceError::InvalidInput("Invalid file name".to_string()))?
            .to_string();

        let mut contents = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut contents)?;
        let cursor = Cursor::new(contents);

        let response = self.client.add(cursor).await?;
        debug!("File added to IPFS with CID: {}", response.hash);
        self.client.pin_add(&response.hash, true).await?;
        debug!("File pinned: {}", response.hash);

        let metadata = FileMetadata {
            cid: response.hash.clone(),
            name: file_name,
            size: file_size,
            timestamp: Utc::now(),
        };

        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            "INSERT INTO file_metadata (cid, name, size, timestamp) VALUES (:cid, :name, :size, :timestamp)",
            params! {
                "cid" => &metadata.cid,
                "name" => &metadata.name,
                "size" => &metadata.size,
                "timestamp" => metadata.timestamp.to_rfc3339(),
            },
        )
        .await?;
        info!("File metadata stored: {}", metadata.cid);

        Ok(metadata)
    }

    async fn download_file(&self, cid: &str, output_path: &str) -> Result<(), ServiceError> {
        if cid.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "CID cannot be empty".to_string(),
            ));
        }

        let mut stream = self.client.cat(cid);
        let mut bytes = Vec::new();

        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
        }

        std::fs::write(output_path, bytes)?;
        info!("File downloaded to: {}", output_path);
        Ok(())
    }

    async fn delete_file(&self, cid: &str) -> Result<(), ServiceError> {
        if cid.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "CID cannot be empty".to_string(),
            ));
        }

        self.client.pin_rm(cid, true).await?;
        debug!("File unpinned: {}", cid);

        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            "DELETE FROM file_metadata WHERE cid = :cid",
            params! { "cid" => cid },
        )
        .await?;
        let affected = conn.affected_rows();
        if affected > 0 {
            info!("File metadata deleted: {}", cid);
        } else {
            warn!("No metadata found for CID: {}", cid);
        }
        Ok(())
    }

    async fn list_pins(&self) -> Result<Vec<String>, ServiceError> {
        let pins = self.client.pin_ls(Some("recursive"), None).await?;
        Ok(pins.keys.into_iter().map(|(cid, _)| cid).collect())
    }

    async fn get_file_metadata(&self, cid: &str) -> Result<Option<FileMetadata>, ServiceError> {
        if cid.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "CID cannot be empty".to_string(),
            ));
        }

        let mut conn = self.db_pool.get_conn().await?;
        let result = conn
            .query_first::<mysql_async::Row, _>(format!(
                "SELECT cid, name, size, timestamp FROM file_metadata WHERE cid = '{}'",
                cid
            ))
            .await?;

        Ok(result.map(|row| {
            let cid: String = row.get("cid").expect("CID should be present");
            let name: String = row.get("name").expect("Name should be present");
            let size: u64 = row.get("size").expect("Size should be present");
            let timestamp_str: String = row.get("timestamp").expect("Timestamp should be present");

            FileMetadata {
                cid,
                name,
                size,
                timestamp: DateTime::parse_from_rfc3339(&timestamp_str)
                    .unwrap_or_else(|e| {
                        warn!("Failed to parse timestamp '{}': {}", timestamp_str, e);
                        Utc::now().into()
                    })
                    .into(),
            }
        }))
    }
}

async fn upload(
    service: web::Data<Arc<IPFSService>>,
    req: web::Json<UploadRequest>,
) -> Result<HttpResponse, ActixError> {
    info!("Upload request for file: {}", req.file_path);
    let metadata = service.upload_file(&req.file_path).await?;
    Ok(HttpResponse::Ok().json(metadata))
}

async fn download(
    service: web::Data<Arc<IPFSService>>,
    req: web::Json<DownloadRequest>,
) -> Result<HttpResponse, ActixError> {
    info!("Download request for CID: {}", req.cid);
    service.download_file(&req.cid, &req.output_path).await?;
    Ok(HttpResponse::Ok().body("File downloaded successfully"))
}

async fn delete(
    service: web::Data<Arc<IPFSService>>,
    req: web::Json<DeleteRequest>,
) -> Result<HttpResponse, ActixError> {
    info!("Delete request for CID: {}", req.cid);
    service.delete_file(&req.cid).await?;
    Ok(HttpResponse::Ok().body("File deleted successfully"))
}

async fn list_pins(service: web::Data<Arc<IPFSService>>) -> Result<HttpResponse, ActixError> {
    info!("List pins request received");
    let pins = service.list_pins().await?;
    Ok(HttpResponse::Ok().json(pins))
}

async fn get_metadata(
    service: web::Data<Arc<IPFSService>>,
    path: web::Path<String>,
) -> Result<HttpResponse, ActixError> {
    let cid = path.into_inner();
    info!("Metadata request for CID: {}", cid);
    match service.get_file_metadata(&cid).await? {
        Some(metadata) => Ok(HttpResponse::Ok().json(metadata)),
        None => Ok(HttpResponse::NotFound().body("File not found")),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    let config = Config::from_env().expect("Failed to load configuration");

    debug!("Initializing IPFS service...");
    let service = match IPFSService::new(&config).await {
        Ok(service) => Arc::new(service),
        Err(e) => {
            error!("Failed to initialize IPFS service: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    };
    debug!("IPFS service initialized successfully");

    let bind_address = config.bind_address.clone();
    info!("Starting server at {}", bind_address);

    HttpServer::new(move || {
        let app = App::new()
            .app_data(web::Data::new(service.clone()))
            .route("/upload", web::post().to(upload))
            .route("/download", web::post().to(download))
            .route("/delete", web::post().to(delete))
            .route("/pins", web::get().to(list_pins))
            .route("/metadata/{cid}", web::get().to(get_metadata));
        debug!("Application routes configured");
        app
    })
    .bind(&bind_address)?
    .run()
    .await
}
