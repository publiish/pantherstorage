use actix_web::{http::StatusCode, HttpResponse};
use hyper::http::uri::InvalidUri;
use serde::Serialize;
use thiserror::Error;

/// Possible errors that can occur in the service
#[derive(Debug, Error)]
pub enum ServiceError {
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

/// Error response for API endpoints
#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
    message: String,
}
