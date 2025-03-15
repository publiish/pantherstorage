use actix_service::{Service, Transform};
use actix_web::http::StatusCode;
use actix_web::{
    error::Error as ActixError, middleware, web, App, HttpRequest, HttpResponse, HttpServer,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use dotenv::dotenv;
use env_logger::Env;
use futures::stream::StreamExt;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use hyper::http::uri::InvalidUri;
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use log::{error, info};
use mysql_async::{prelude::*, Opts, Pool};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{Cursor, Read},
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use validator::{Validate, ValidationError};

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
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Rate limit exceeded")]
    RateLimit,
}

impl actix_web::error::ResponseError for ServiceError {
    fn status_code(&self) -> StatusCode {
        match self {
            ServiceError::InvalidInput(_) | ServiceError::Validation(_) => StatusCode::BAD_REQUEST,
            ServiceError::Auth(_) => StatusCode::UNAUTHORIZED,
            ServiceError::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorResponse {
            error: self.status_code().to_string(),
            message: self.to_string(),
        })
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
    user_id: i32,
}

#[derive(Debug, Validate, Deserialize)]
struct UploadRequest {
    #[validate(length(min = 1, max = 255))]
    file_path: String,
}

#[derive(Debug, Validate, Deserialize)]
struct DownloadRequest {
    #[validate(length(min = 1))]
    cid: String,
    #[validate(length(min = 1, max = 255))]
    output_path: String,
}

#[derive(Debug, Validate, Deserialize)]
struct DeleteRequest {
    #[validate(length(min = 1))]
    cid: String,
}

#[derive(Debug, Validate, Deserialize)]
struct SignupRequest {
    #[validate(length(min = 3, max = 50))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(length(min = 8))]
    #[validate(custom(function = "validate_password"))]
    password: String,
}

#[derive(Debug, Validate, Deserialize)]
struct SigninRequest {
    #[validate(email)]
    email: String,
    #[validate(length(min = 8))]
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    if !password.chars().any(char::is_uppercase)
        || !password.chars().any(char::is_numeric)
        || !password.chars().any(|c| "!@#$%^&*".contains(c))
    {
        return Err(ValidationError::new("Password must contain at least one uppercase letter, one number, and one special character"));
    }
    Ok(())
}

// Custom rate limiter
#[derive(Clone)]
struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, (u64, u32)>>>,
    max_requests: u32,
    // in seconds
    interval: u64,
}

impl RateLimiter {
    fn new(max_requests: u32, interval: u64) -> Self {
        RateLimiter {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            interval,
        }
    }

    fn check_rate_limit(&self, ip: &str) -> Result<(), ServiceError> {
        let mut requests = self.requests.lock().map_err(|_| ServiceError::Internal)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = requests.entry(ip.to_string()).or_insert((now, 0));
        if now - entry.0 >= self.interval {
            *entry = (now, 1);
        } else if entry.1 >= self.max_requests {
            return Err(ServiceError::RateLimit);
        } else {
            entry.1 += 1;
        }
        Ok(())
    }
}

// Middleware implementation
impl<S, B> Transform<S, actix_web::dev::ServiceRequest> for RateLimiter
where
    S: Service<
            actix_web::dev::ServiceRequest,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = ActixError,
        > + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = RateLimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimiterMiddleware {
            service,
            rate_limiter: self.clone(),
        })
    }
}

pub struct RateLimiterMiddleware<S> {
    service: S,
    rate_limiter: RateLimiter,
}

impl<S, B> Service<actix_web::dev::ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<
            actix_web::dev::ServiceRequest,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = ActixError,
        > + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: actix_web::dev::ServiceRequest) -> Self::Future {
        let ip = req
            .peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match self.rate_limiter.check_rate_limit(&ip) {
            Ok(()) => {
                let fut = self.service.call(req);
                Box::pin(async move { fut.await })
            }
            Err(e) => Box::pin(async move { Err(e.into()) }),
        }
    }
}

struct Config {
    ipfs_node: String,
    database_url: String,
    bind_address: String,
    jwt_secret: String,
}

impl Config {
    fn from_env() -> Result<Self, env::VarError> {
        dotenv().ok();
        Ok(Config {
            ipfs_node: env::var("IPFS_NODE")
                .unwrap_or_else(|_| "http://127.0.0.1:5001".to_string()),
            database_url: env::var("DATABASE_URL")?,
            bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8081".to_string()),
            jwt_secret: env::var("JWT_SECRET")?,
        })
    }
}

struct AppState {
    ipfs_service: Arc<IPFSService>,
}

struct IPFSService {
    client: IpfsClient,
    db_pool: Pool,
    url: String,
    jwt_secret: String,
}

impl IPFSService {
    async fn new(config: &Config) -> Result<Self, ServiceError> {
        let client = IpfsClient::from_str(&config.ipfs_node)?;
        let version = client.version().await?;
        info!(
            "Connected to IPFS node: {} (version: {})",
            config.ipfs_node, version.version
        );

        let opts = Opts::from_url(&config.database_url)?;
        let pool = Pool::new(opts);
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
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_cid (cid),
                INDEX idx_user_id (user_id)
            )",
        )
        .await?;

        info!("Database schema initialized");

        Ok(Self {
            client,
            db_pool: pool,
            url: config.ipfs_node.clone(),
            jwt_secret: config.jwt_secret.clone(),
        })
    }

    async fn signup(&self, req: SignupRequest) -> Result<String, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        let password_hash =
            hash(&req.password, DEFAULT_COST).map_err(|_| ServiceError::Internal)?;

        let mut conn = self.db_pool.get_conn().await?;
        let result = conn.exec_drop(
            "INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)",
            params! {
                "username" => &req.username,
                "email" => &req.email,
                "password_hash" => &password_hash,
            },
        ).await;

        if let Err(mysql_async::Error::Server(err)) = &result {
            if err.code == 1062 {
                // Duplicate entry
                return Err(ServiceError::InvalidInput(
                    "Username or email already exists".to_string(),
                ));
            }
        }
        result?;

        let user_id: i32 = conn
            .query_first("SELECT LAST_INSERT_ID()")
            .await?
            .ok_or(ServiceError::Internal)?;

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + Duration::days(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| ServiceError::Internal)?;

        info!("New user signed up: {}", req.email);
        Ok(token)
    }

    async fn signin(&self, req: SigninRequest) -> Result<String, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        let mut conn = self.db_pool.get_conn().await?;
        let user: Option<(i32, String)> = conn
            .exec_first(
                "SELECT id, password_hash FROM users WHERE email = :email",
                params! { "email" => &req.email },
            )
            .await?;

        let (user_id, password_hash) =
            user.ok_or(ServiceError::Auth("Invalid credentials".to_string()))?;

        if !verify(&req.password, &password_hash).map_err(|_| ServiceError::Internal)? {
            return Err(ServiceError::Auth("Invalid credentials".to_string()));
        }

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + Duration::days(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| ServiceError::Internal)?;

        info!("User signed in: {}", req.email);
        Ok(token)
    }

    async fn upload_file(
        &self,
        file_path: &str,
        user_id: i32,
    ) -> Result<FileMetadata, ServiceError> {
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
            .ok_or(ServiceError::InvalidInput("Invalid file path".to_string()))?
            .to_str()
            .ok_or(ServiceError::InvalidInput("Invalid file name".to_string()))?
            .to_string();

        let mut contents = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut contents)?;
        let cursor = Cursor::new(contents);

        let response = self.client.add(cursor).await?;
        self.client.pin_add(&response.hash, true).await?;

        let metadata = FileMetadata {
            cid: response.hash.clone(),
            name: file_name,
            size: file_size,
            timestamp: Utc::now(),
            user_id,
        };

        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            "INSERT INTO file_metadata (cid, name, size, timestamp, user_id) VALUES (:cid, :name, :size, :timestamp, :user_id)",
            params! {
                "cid" => &metadata.cid,
                "name" => &metadata.name,
                "size" => &metadata.size,
                "timestamp" => metadata.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                "user_id" => user_id,
            },
        ).await?;

        info!("File uploaded by user {}: {}", user_id, metadata.cid);
        Ok(metadata)
    }

    async fn download_file(
        &self,
        cid: &str,
        output_path: &str,
        user_id: i32,
    ) -> Result<(), ServiceError> {
        let metadata = self
            .get_file_metadata(cid)
            .await?
            .ok_or(ServiceError::InvalidInput("File not found".to_string()))?;

        if metadata.user_id != user_id {
            return Err(ServiceError::Auth(
                "Not authorized to access this file".to_string(),
            ));
        }

        let mut stream = self.client.cat(cid);
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
        }

        std::fs::write(output_path, &bytes)?;
        info!("File downloaded by user {}: {}", user_id, cid);
        Ok(())
    }

    async fn delete_file(&self, cid: &str, user_id: i32) -> Result<(), ServiceError> {
        let metadata = self
            .get_file_metadata(cid)
            .await?
            .ok_or(ServiceError::InvalidInput("File not found".to_string()))?;

        if metadata.user_id != user_id {
            return Err(ServiceError::Auth(
                "Not authorized to delete this file".to_string(),
            ));
        }

        self.client.pin_rm(cid, true).await?;
        let mut conn = self.db_pool.get_conn().await?;
        conn.exec_drop(
            "DELETE FROM file_metadata WHERE cid = :cid",
            params! { "cid" => cid },
        )
        .await?;

        info!("File deleted by user {}: {}", user_id, cid);
        Ok(())
    }

    async fn list_pins(&self, user_id: i32) -> Result<Vec<String>, ServiceError> {
        let mut conn = self.db_pool.get_conn().await?;
        let cids: Vec<String> = conn
            .exec_map(
                "SELECT cid FROM file_metadata WHERE user_id = :user_id",
                params! { "user_id" => user_id },
                |cid| cid,
            )
            .await?;

        Ok(cids)
    }

    async fn get_file_metadata(&self, cid: &str) -> Result<Option<FileMetadata>, ServiceError> {
        let mut conn = self.db_pool.get_conn().await?;
        let result = conn
            .query_first::<mysql_async::Row, _>(format!(
                "SELECT cid, name, size, timestamp, user_id FROM file_metadata WHERE cid = '{}'",
                cid
            ))
            .await?;

        Ok(result.map(|row| FileMetadata {
            cid: row.get("cid").unwrap(),
            name: row.get("name").unwrap(),
            size: row.get("size").unwrap(),
            timestamp: Utc::now(),
            user_id: row.get("user_id").unwrap(),
        }))
    }
}

async fn verify_token(req: HttpRequest, service: &IPFSService) -> Result<i32, ServiceError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or(ServiceError::Auth(
            "Missing authorization header".to_string(),
        ))?
        .to_str()
        .map_err(|_| ServiceError::Auth("Invalid header format".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(ServiceError::Auth("Invalid token format".to_string()))?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(service.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| ServiceError::Auth("Invalid token".to_string()))?;

    Ok(token_data
        .claims
        .sub
        .parse::<i32>()
        .map_err(|_| ServiceError::Internal)?)
}

async fn signup(
    state: web::Data<AppState>,
    req: web::Json<SignupRequest>,
) -> Result<HttpResponse, ActixError> {
    let token = state.ipfs_service.signup(req.into_inner()).await?;
    Ok(HttpResponse::Ok().json(AuthResponse { token }))
}

async fn signin(
    state: web::Data<AppState>,
    req: web::Json<SigninRequest>,
) -> Result<HttpResponse, ActixError> {
    let token = state.ipfs_service.signin(req.into_inner()).await?;
    Ok(HttpResponse::Ok().json(AuthResponse { token }))
}

async fn upload(
    state: web::Data<AppState>,
    req: web::Json<UploadRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ActixError> {
    req.validate()
        .map_err(|e| ServiceError::Validation(e.to_string()))?;
    let user_id = verify_token(http_req, &state.ipfs_service).await?;
    let metadata = state
        .ipfs_service
        .upload_file(&req.file_path, user_id)
        .await?;
    Ok(HttpResponse::Ok().json(metadata))
}

async fn download(
    state: web::Data<AppState>,
    req: web::Json<DownloadRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ActixError> {
    req.validate()
        .map_err(|e| ServiceError::Validation(e.to_string()))?;
    let user_id = verify_token(http_req, &state.ipfs_service).await?;
    state
        .ipfs_service
        .download_file(&req.cid, &req.output_path, user_id)
        .await?;
    Ok(HttpResponse::Ok().body("File downloaded successfully"))
}

async fn delete(
    state: web::Data<AppState>,
    req: web::Json<DeleteRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ActixError> {
    req.validate()
        .map_err(|e| ServiceError::Validation(e.to_string()))?;
    let user_id = verify_token(http_req, &state.ipfs_service).await?;
    state.ipfs_service.delete_file(&req.cid, user_id).await?;
    Ok(HttpResponse::Ok().body("File deleted successfully"))
}

async fn list_pins(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ActixError> {
    let user_id = verify_token(http_req, &state.ipfs_service).await?;
    let pins = state.ipfs_service.list_pins(user_id).await?;
    Ok(HttpResponse::Ok().json(pins))
}

async fn get_metadata(
    state: web::Data<AppState>,
    path: web::Path<String>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ActixError> {
    let user_id = verify_token(http_req, &state.ipfs_service).await?;
    let cid = path.into_inner();
    let metadata = state
        .ipfs_service
        .get_file_metadata(&cid)
        .await?
        .ok_or(ServiceError::InvalidInput("File not found".to_string()))?;

    if metadata.user_id != user_id {
        return Err(ServiceError::Auth("Not authorized to access this file".to_string()).into());
    }

    Ok(HttpResponse::Ok().json(metadata))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = Config::from_env().expect("Failed to load configuration");

    let ipfs_service = Arc::new(
        IPFSService::new(&config)
            .await
            .expect("Failed to initialize IPFS service"),
    );
    // 100 requests per minute
    let rate_limiter = RateLimiter::new(100, 60);

    let app_state = web::Data::new(AppState { ipfs_service });

    let bind_address = config.bind_address.clone();
    info!("Starting server at {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .wrap(rate_limiter.clone())
            .service(
                web::scope("/api")
                    .route("/signup", web::post().to(signup))
                    .route("/signin", web::post().to(signin))
                    .route("/upload", web::post().to(upload))
                    .route("/download", web::post().to(download))
                    .route("/delete", web::post().to(delete))
                    .route("/pins", web::get().to(list_pins))
                    .route("/metadata/{cid}", web::get().to(get_metadata)),
            )
    })
    .workers(4)
    .bind(&bind_address)?
    .run()
    .await
}
