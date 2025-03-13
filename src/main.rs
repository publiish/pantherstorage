use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Cursor, Read};
// use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::StreamExt;
use mysql::prelude::*;
use mysql::*;
use serde_with::{serde_as, DisplayFromStr};

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

struct IPFSService {
    clients: Vec<IpfsClient>,
    db_pool: Pool,
}

impl IPFSService {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let clients = vec![
            IpfsClient::from_str("http://127.0.0.1:5001")?,
            IpfsClient::from_str("http://127.0.0.1:5002")?,
            IpfsClient::from_str("http://127.0.0.1:5003")?,
            // IpfsClient::from_str("http://ipfs0:5001")?,
            // IpfsClient::from_str("http://ipfs1:5001")?,
            // IpfsClient::from_str("http://ipfs2:5001")?,
        ];

        let pool = Pool::new("mysql://root:password@localhost:3306/publiish_local")?;
        let mut conn = pool.get_conn()?;
        conn.query_drop(
            r"CREATE TABLE IF NOT EXISTS file_metadata (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                cid VARCHAR(100) NOT NULL,
                name VARCHAR(255) NOT NULL,
                size BIGINT NOT NULL,
                timestamp DATETIME NOT NULL
            )",
        )?;

        Ok(Self {
            clients,
            db_pool: pool,
        })
    }

    async fn upload_file(
        &self,
        file_path: &str,
    ) -> Result<FileMetadata, Box<dyn std::error::Error>> {
        let mut file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        let file_name = std::path::Path::new(file_path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let cursor = Cursor::new(contents);

        let response = self.clients[0].add(cursor).await?;
        for client in &self.clients {
            client.pin_add(&response.hash, true).await?;
        }

        let metadata = FileMetadata {
            cid: response.hash.clone(),
            name: file_name,
            size: file_size,
            timestamp: Utc::now(),
        };

        let mut conn = self.db_pool.get_conn()?;
        conn.exec_drop(
            "INSERT INTO file_metadata (cid, name, size, timestamp) VALUES (?, ?, ?, ?)",
            (
                &metadata.cid,
                &metadata.name,
                &metadata.size,
                metadata.timestamp.to_rfc3339(),
            ),
        )?;

        Ok(metadata)
    }

    async fn download_file(
        &self,
        cid: &str,
        output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = self.clients[0].cat(cid);
        let mut bytes = Vec::new();

        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
        }

        std::fs::write(output_path, bytes)?;
        Ok(())
    }

    async fn delete_file(&self, cid: &str) -> Result<(), Box<dyn std::error::Error>> {
        for client in &self.clients {
            client.pin_rm(cid, true).await?;
        }

        let mut conn = self.db_pool.get_conn()?;
        conn.exec_drop("DELETE FROM file_metadata WHERE cid = ?", (cid,))?;
        Ok(())
    }

    async fn list_pins(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let pins = self.clients[0].pin_ls(Some("recursive"), None).await?;
        Ok(pins.keys.into_iter().map(|(cid, _)| cid).collect())
    }

    async fn get_file_metadata(
        &self,
        cid: &str,
    ) -> Result<Option<FileMetadata>, Box<dyn std::error::Error>> {
        let mut conn = self.db_pool.get_conn()?;
        let result: Option<(String, String, u64, String)> = conn.exec_first(
            "SELECT cid, name, size, timestamp FROM file_metadata WHERE cid = ?",
            (cid,),
        )?;

        Ok(result.map(|(cid, name, size, timestamp)| FileMetadata {
            cid,
            name,
            size,
            timestamp: DateTime::parse_from_rfc3339(&timestamp).unwrap().into(),
        }))
    }
}

async fn upload(service: web::Data<IPFSService>, req: web::Json<UploadRequest>) -> impl Responder {
    match service.upload_file(&req.file_path).await {
        Ok(metadata) => HttpResponse::Ok().json(metadata),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn download(
    service: web::Data<IPFSService>,
    req: web::Json<DownloadRequest>,
) -> impl Responder {
    match service.download_file(&req.cid, &req.output_path).await {
        Ok(()) => HttpResponse::Ok().body("File downloaded successfully"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn delete(service: web::Data<IPFSService>, req: web::Json<DeleteRequest>) -> impl Responder {
    match service.delete_file(&req.cid).await {
        Ok(()) => HttpResponse::Ok().body("File deleted successfully"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn list_pins(service: web::Data<IPFSService>) -> impl Responder {
    match service.list_pins().await {
        Ok(pins) => HttpResponse::Ok().json(pins),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn get_metadata(service: web::Data<IPFSService>, path: web::Path<String>) -> impl Responder {
    match service.get_file_metadata(&path.into_inner()).await {
        Ok(Some(metadata)) => HttpResponse::Ok().json(metadata),
        Ok(None) => HttpResponse::NotFound().body("File not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let service = IPFSService::new()
        .await
        .expect("Failed to initialize IPFS service");
    let service_data = web::Data::new(service);

    HttpServer::new(move || {
        App::new()
            .app_data(service_data.clone())
            .route("/upload", web::post().to(upload))
            .route("/download", web::post().to(download))
            .route("/delete", web::post().to(delete))
            .route("/pins", web::get().to(list_pins))
            .route("/metadata/{cid}", web::get().to(get_metadata))
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}
