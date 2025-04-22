use crate::services::{ipfs_service::IPFSService, brand_service::BrandService};
use actix_web::web;
use std::sync::Arc;

pub mod auth;
pub mod file;
pub mod brand;

#[derive(Clone)]
pub struct AppState {
    pub ipfs_service: Arc<IPFSService>,
    pub brand_service: Arc<BrandService>,
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(auth::init_routes)
            .configure(file::init_routes)
            .configure(brand::init_routes),
    );
}
