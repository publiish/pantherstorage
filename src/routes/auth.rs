use crate::models::{auth::AuthResponse, requests::*};
use actix_web::{web, HttpResponse};

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/signup", web::post().to(signup))
        .route("/signin", web::post().to(signin));
}

/// Handles user signup requests
/// POST /api/signup
async fn signup(
    state: web::Data<super::AppState>,
    req: web::Json<SignupRequest>,
) -> Result<HttpResponse, actix_web::error::Error> {
    let token = state.ipfs_service.signup(req.into_inner()).await?;
    Ok(HttpResponse::Ok().json(AuthResponse { token }))
}

/// Handles user signin requests
/// POST /api/signin
async fn signin(
    state: web::Data<super::AppState>,
    req: web::Json<SigninRequest>,
) -> Result<HttpResponse, actix_web::error::Error> {
    let token = state.ipfs_service.signin(req.into_inner()).await?;
    Ok(HttpResponse::Ok().json(AuthResponse { token }))
}
