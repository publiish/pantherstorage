use crate::{
    database, errors::ServiceError, models::requests::*, services::ipfs_service::IPFSService,
};
use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use mime_guess::from_path;
use sanitize_filename::sanitize;
use std::collections::HashMap;
use validator::Validate;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/upload", web::post().to(upload))
        .route("/download/{cid}", web::get().to(download))
        .route("/delete", web::post().to(delete))
        .route("/pins", web::get().to(list_pins))
        .route("/metadata/{cid}", web::get().to(get_metadata))
        .route(
            "/upload/status/{task_id}",
            web::get().to(get_upload_status_handler),
        );
}

/// Handles file upload requests via multipart form data
/// POST /api/upload?async=true (optional query param for async behavior)
async fn upload(
    state: web::Data<super::AppState>,
    mut payload: Multipart,
    http_req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, actix_web::error::Error> {
    let user_id = verify_token(http_req, &state.ipfs_service).await?;
    let is_async = query.get("async").map_or(false, |v| v == "true");

    let mut file_bytes = Vec::new();
    let mut file_name = "unnamed_file".to_string();

    // Process the multipart stream
    while let Some(field) = payload.next().await {
        let mut field = field?;
        if let Some(content_disposition) = field.content_disposition() {
            if let Some(name) = content_disposition.get_filename() {
                file_name = sanitize(name);
            }
        }
        while let Some(chunk) = field.next().await {
            file_bytes.extend(chunk?);
        }
    }

    if file_bytes.is_empty() {
        return Err(ServiceError::InvalidInput("Empty file uploaded".to_string()).into());
    }

    let file_stream = futures::stream::iter(vec![Ok(file_bytes)]);

    if is_async {
        // Asynchronous upload
        let status = state
            .ipfs_service
            .upload_file(file_stream, file_name, user_id)
            .await?;
        Ok(HttpResponse::Ok().json(status))
    } else {
        // Synchronous upload
        let metadata = state
            .ipfs_service
            .upload(file_stream, file_name, user_id)
            .await?;
        Ok(HttpResponse::Ok()
            .append_header(("X-CID", metadata.cid.clone()))
            .json(metadata))
    }
}

/// Handles requests to get the status of an upload task
/// GET /api/upload_file/status/{task_id}
async fn get_upload_status_handler(
    state: web::Data<super::AppState>,
    path: web::Path<String>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
    let task_id = path.into_inner();
    let user_id = verify_token(http_req, &state.ipfs_service).await?;

    let status = database::get_upload_status(&state.ipfs_service, &task_id, user_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get upload status for task {}: {}", task_id, e);
            actix_web::error::ErrorInternalServerError(e)
        })?;

    Ok(HttpResponse::Ok().json(status))
}

/// Serves file content directly to the browser
/// GET /api/download/{cid}
async fn download(
    state: web::Data<super::AppState>,
    path: web::Path<String>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
    let cid = path.into_inner();
    let user_id = verify_token(http_req, &state.ipfs_service).await?;

    let metadata = state
        .ipfs_service
        .get_file_metadata(&cid)
        .await?
        .ok_or_else(|| ServiceError::InvalidInput("File not found".to_string()))?;

    if metadata.user_id != user_id {
        return Err(ServiceError::Auth("Not authorized to access this file".to_string()).into());
    }

    let file_bytes = state.ipfs_service.fetch_file_bytes(&cid, user_id).await?;

    // Determine MIME type based on file extension, default to octet-stream
    let mime_type = from_path(&metadata.name).first_or_octet_stream();

    Ok(HttpResponse::Ok()
        .content_type(mime_type.to_string())
        .append_header((
            "Content-Disposition",
            format!("inline; filename=\"{}\"", metadata.name),
        ))
        .body(file_bytes))
}

/// Handles file deletion requests
/// POST /api/delete
async fn delete(
    state: web::Data<super::AppState>,
    req: web::Json<DeleteRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
    let inner = req.into_inner();
    inner
        .validate()
        .map_err(|e| ServiceError::Validation(e.to_string()))?;

    let user_id = verify_token(http_req, &state.ipfs_service).await?;

    state
        .ipfs_service
        .delete_file(&inner.cid, user_id)
        .await
        .map_err(|e| {
            log::error!(
                "Failed to delete file CID {} for user {}: {}",
                inner.cid,
                user_id,
                e
            );
            match e {
                ServiceError::InvalidInput(_) => actix_web::error::ErrorNotFound(e),
                ServiceError::Auth(_) => actix_web::error::ErrorForbidden(e),
                _ => actix_web::error::ErrorInternalServerError(e),
            }
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "File deleted successfully",
        "cid": inner.cid
    })))
}

/// Lists all pinned files for the authenticated user
/// GET /api/pins
async fn list_pins(
    state: web::Data<super::AppState>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
    let user_id = verify_token(http_req, &state.ipfs_service).await?;
    let pins = state.ipfs_service.list_pins(user_id).await?;
    Ok(HttpResponse::Ok().json(pins))
}

/// Retrieves metadata for a specific file
/// GET /api/metadata/{cid}
async fn get_metadata(
    state: web::Data<super::AppState>,
    path: web::Path<String>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
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

/// Verifies token from request headers using PQC signature verification
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

    let claims = service.verify_token(token)?;
    claims
        .sub
        .parse::<i32>()
        .map_err(|_| ServiceError::Internal("Failed to parse user ID".to_string()))
}
