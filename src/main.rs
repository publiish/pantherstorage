use actix_web::{middleware as actix_middleware, App, HttpServer};
use env_logger::Env;
use std::io;

mod config;
mod errors;
mod middleware;
mod models;
mod routes;
mod services;

use config::Config;
use services::ipfs_service::IPFSService;

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = Config::from_env().expect("Failed to load configuration");

    let ipfs_service = IPFSService::new(&config)
        .await
        .expect("Failed to initialize IPFS service");
    let app_state = routes::AppState {
        ipfs_service: std::sync::Arc::new(ipfs_service),
    };
    let rate_limiter = services::rate_limiter::RateLimiter::new(100, 60);

    let bind_address = config.bind_address.clone();
    log::info!("Starting server at {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(app_state.clone()))
            .wrap(actix_middleware::Logger::default())
            .wrap(rate_limiter.clone())
            .configure(routes::init_routes)
    })
    .workers(4)
    .bind(&bind_address)?
    .run()
    .await
}
