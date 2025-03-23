use actix_web::{middleware as actix_middleware, App, HttpServer};
use env_logger::Env;
use std::io;
use tokio::time::{interval, Duration};

mod config;
mod errors;
mod middleware;
mod models;
mod routes;
mod services;
mod stream;
mod utils;

use config::Config;
use services::ipfs_service::IPFSService;

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = Config::from_env().expect("Failed to load configuration");

    let ipfs_service = IPFSService::new(&config)
        .await
        .expect("Failed to initialize IPFS service");
    let ipfs_service = std::sync::Arc::new(ipfs_service);
    let app_state = routes::AppState {
        ipfs_service: ipfs_service.clone(),
    };
    let rate_limiter = services::rate_limiter::RateLimiter::new(100, 60);

    start_task_cleanup(ipfs_service.clone());

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

/// Spawns a background task to periodically clean up old tasks
fn start_task_cleanup(ipfs_service: std::sync::Arc<IPFSService>) {
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(7200));
        loop {
            interval.tick().await;
            match utils::cleanup_old_tasks(&ipfs_service.db_pool, ipfs_service.tasks.clone()).await
            {
                Ok(()) => log::info!("Task cleanup completed successfully"),
                Err(e) => log::error!("Task cleanup failed: {}", e),
            }
        }
    });
}
