use crate::services::ipfs_service::IPFSService;
use actix_web::web;
use std::sync::Arc;

pub mod auth;
pub mod file;

#[derive(Clone)]
pub struct AppState {
    pub ipfs_service: Arc<IPFSService>,
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(auth::init_routes)
            .configure(file::init_routes),
    );
}
