use crate::models::auth::Claims;
use crate::{errors::ServiceError, models::requests::*, services::ipfs_service::IPFSService};
use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use jsonwebtoken::{decode, DecodingKey, Validation};
use mime_guess::from_path;
use validator::Validate;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/upload", web::post().to(upload))
        .route("/download/{cid}", web::get().to(download))
        .route("/delete", web::post().to(delete))
        .route("/pins", web::get().to(list_pins))
        .route("/metadata/{cid}", web::get().to(get_metadata));
}

/// Handles file upload requests via multipart form data
/// POST /api/upload
async fn upload(
    state: web::Data<super::AppState>,
    mut payload: Multipart,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
    let user_id = verify_token(http_req, &state.ipfs_service).await?;

    // Process the multipart stream
    while let Some(mut field) = payload.try_next().await? {
        let file_name = field
            .content_disposition()
            .and_then(|cd| cd.get_filename())
            .map_or("unnamed_file".to_string(), |n| n.to_string());

        // Collect file contents into a Vec<u8>
        let mut file_contents = Vec::new();
        while let Some(chunk) = field.try_next().await? {
            file_contents.extend_from_slice(&chunk);
        }

        let metadata = state
            .ipfs_service
            .upload_file(file_contents, file_name, user_id)
            .await?;
        return Ok(HttpResponse::Ok().json(metadata));
    }

    Err(ServiceError::InvalidInput("No file provided in multipart data".to_string()).into())
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
        .ok_or(ServiceError::InvalidInput("File not found".to_string()))?;

    let file_bytes = state.ipfs_service.fetch_file_bytes(&cid, user_id).await?;

    // Determine MIME type based on file extension, default to octet-stream
    let mime_type = from_path(&metadata.name).first_or_octet_stream();

    Ok(HttpResponse::Ok()
        .content_type(mime_type.to_string())
        .header(
            "Content-Disposition",
            format!("inline; filename=\"{}\"", metadata.name),
        )
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
    state.ipfs_service.delete_file(&inner.cid, user_id).await?;
    Ok(HttpResponse::Ok().body("File deleted successfully"))
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

/// Verifies JWT token from request headers
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
