use crate::{
    models::brand::{BrandProfileUpdate, BrandRegisterRequest},
    services::brand_service::BrandService,
    routes::AppState,
};
use actix_web::{web, HttpRequest, HttpResponse};
use validator::Validate;
use serde_json::json;
use crate::errors::ServiceError;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/brands/stats/{id}", web::get().to(get_brand_stats))
        .route("/brands", web::post().to(update_brand_profile))
        .route("/brands/did", web::post().to(register_brand_did));
}

async fn get_brand_stats(
    state: web::Data<AppState>,
    path: web::Path<i64>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let brand_id = path.into_inner();
    verify_auth(http_req)?;

    match state.brand_service.get_brand_stats(brand_id).await {
        Ok(stats) => Ok(HttpResponse::Ok().json(stats)),
        Err(ServiceError::NotFound) => {
            log::warn!("Brand not found: {}", brand_id);
            Ok(HttpResponse::NotFound().json(json!({ "error": "Brand not found" })))
        }
        Err(e) => {
            log::error!("Failed to get brand stats for ID {}: {}", brand_id, e);
            Ok(HttpResponse::InternalServerError().json(json!({ "error": "Failed to fetch brand stats" })))
        }
    }
    
}


async fn update_brand_profile(
    state: web::Data<AppState>,
    req: web::Json<BrandProfileUpdate>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
    let profile_data = req.into_inner();
    profile_data
        .validate()
        .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;
    verify_auth(http_req)?;

    let brand_service = &state.brand_service;

    match brand_service
        .update_brand_profile(profile_data.brand_id, profile_data)
        .await
    {
        Ok(_) => Ok(HttpResponse::Ok().json(json!({
            "message": "Brand profile updated successfully"
        }))),
        Err(e) => {
            log::error!("Failed to update brand profile: {}", e);
            Err(actix_web::error::ErrorInternalServerError("Failed to update brand profile"))
        }
    }
}

async fn register_brand_did(
    state: web::Data<AppState>,
    req: web::Json<BrandRegisterRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, actix_web::error::Error> {
    let data = req.into_inner();
    data.validate()
        .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;
    verify_auth(http_req)?;

    let brand_service = &state.brand_service;

    match brand_service.register_brand_did(data.brand_id, data.did).await {
        Ok(_) => Ok(HttpResponse::Ok().json(json!({
            "message": "DID registered successfully"
        }))),
        Err(e) => {
            log::error!("Failed to register DID: {}", e);
            Err(actix_web::error::ErrorInternalServerError("Failed to register DID"))
        }
    }
}

fn verify_auth(req: HttpRequest) -> Result<(), actix_web::error::Error> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing authorization header"))?;
    let token = auth_header
        .to_str()
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid header format"))?;
    if !token.starts_with("Bearer ") {
        return Err(actix_web::error::ErrorUnauthorized("Invalid token format"));
    }
    Ok(())
}
