use actix_web::{http::StatusCode, HttpResponse};
use base64::DecodeError as Base64DecodeError;
use hyper::http::uri::InvalidUri;
use serde::Serialize;
use serde_json::Error as SerdeJsonError;
use std::sync::PoisonError;
use thiserror::Error;

/// All service-level errors that can be returned by the API.
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

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Brand not found")]
    NotFound,
    
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
            error: self.status_code().as_str().to_string(),
            message: self.to_string(),
        })
    }
}

impl From<bcrypt::BcryptError> for ServiceError {
    fn from(err: bcrypt::BcryptError) -> Self {
        ServiceError::Internal(format!("Password hashing error: {}", err))
    }
}

impl From<validator::ValidationErrors> for ServiceError {
    fn from(err: validator::ValidationErrors) -> Self {
        ServiceError::Validation(err.to_string())
    }
}

impl From<actix_multipart::MultipartError> for ServiceError {
    fn from(err: actix_multipart::MultipartError) -> Self {
        ServiceError::Internal(format!("Multipart error: {}", err))
    }
}

impl<T> From<PoisonError<T>> for ServiceError {
    fn from(err: PoisonError<T>) -> Self {
        ServiceError::Internal(format!("Mutex lock failed: {}", err))
    }
}

impl From<SerdeJsonError> for ServiceError {
    fn from(err: SerdeJsonError) -> Self {
        ServiceError::Internal(format!("Serialization error: {}", err))
    }
}

impl From<Base64DecodeError> for ServiceError {
    fn from(err: Base64DecodeError) -> Self {
        ServiceError::Auth(format!("Base64 decoding error: {}", err))
    }
}

/// Error response returned to the client.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}
