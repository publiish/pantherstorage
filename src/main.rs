use actix_web::{middleware as actix_middleware, App, HttpServer};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use clap::{Parser, Subcommand};
use env_logger::Env;
use std::io;
use std::sync::Arc;
use tokio::time::{interval, Duration};

mod config;
mod database;
mod errors;
mod middleware;
mod models;
mod routes;
mod services;
mod stream;
mod utils;

use config::Config;
use middleware::rate_limiter::UserRateLimiter;
use services::ipfs_service::IPFSService;
use services::brand_service::BrandService;
// Post-quantum crypto imports
use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Generate post-quantum cryptographic keys
#[derive(Subcommand)]
enum Commands {
    /// cargo run -- generate-keys
    /// cargo run -- generate-keys --output /path/to/keys
    GenerateKeys {
        /// Output directory for keys (default: current directory)
        #[arg(short, long, default_value = ".")]
        output: String,
    },
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::GenerateKeys { output }) => {
            generate_keys(&output)?;
            Ok(())
        }
        None => start_server().await,
    }
}

fn generate_keys(output_dir: &str) -> io::Result<()> {
    std::fs::create_dir_all(output_dir)?;

    let (pk_kem, sk_kem) = kyber1024::keypair();
    let (pk_sign, sk_sign) = dilithium5::keypair();

    let pk_kem_b64 = Base64Engine.encode(pk_kem.as_bytes());
    let sk_kem_b64 = Base64Engine.encode(sk_kem.as_bytes());
    let pk_sign_b64 = Base64Engine.encode(pk_sign.as_bytes());
    let sk_sign_b64 = Base64Engine.encode(sk_sign.as_bytes());

    std::fs::write(format!("{}/kyber1024_public.key", output_dir), pk_kem_b64)?;
    std::fs::write(format!("{}/kyber1024_secret.key", output_dir), sk_kem_b64)?;
    std::fs::write(format!("{}/dilithium5_public.key", output_dir), pk_sign_b64)?;
    std::fs::write(format!("{}/dilithium5_secret.key", output_dir), sk_sign_b64)?;

    log::info!(
        "Base64-encoded keys generated successfully in {}:",
        output_dir
    );
    println!("- kyber1024_public.key (KEM public key)");
    println!("- kyber1024_secret.key (KEM secret key)");
    println!("- dilithium5_public.key (Signature public key)");
    println!("- dilithium5_secret.key (Signature secret key)");

    Ok(())
}

async fn start_server() -> io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let config = Config::from_env().map_err(|e| {
        log::error!("Failed to load configuration: {}", e);
        io::Error::new(io::ErrorKind::Other, "Configuration loading failed")
    })?;

    let db_pool = database::create_pool(&config.database_url); // ✅ NEW

    let ipfs_service = Arc::new(
        IPFSService::new(&config).await.map_err(|e| {
            log::error!("Failed to initialize IPFS service: {}", e);
            io::Error::new(io::ErrorKind::Other, "IPFS service initialization failed")
        })?,
    );

    let brand_service = Arc::new(BrandService::new(db_pool.clone())); // ✅ FIXED
    
    
    let app_state = routes::AppState {
        ipfs_service: ipfs_service.clone(),
        brand_service: brand_service.clone(),
    };

    let rate_limiter = UserRateLimiter::new();

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
    .workers(num_cpus::get().min(8))
    .bind(&bind_address)
    .map_err(|e| {
        log::error!("Failed to bind server to {}: {}", bind_address, e);
        e
    })?
    .run()
    .await
}

fn start_task_cleanup(ipfs_service: Arc<IPFSService>) {
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(7200));
        loop {
            interval.tick().await;
            match utils::cleanup_old_tasks(&ipfs_service.db_pool, ipfs_service.tasks.clone()).await {
                Ok(()) => log::info!("Task cleanup completed successfully"),
                Err(e) => log::error!("Task cleanup failed: {}", e),
            }
            ipfs_service.cleanup_rate_limiters().await;
        }
    });
}

pub mod crypto_utils {
    use super::*;

    pub fn load_kyber_keys(
        pub_path: &str,
        sec_path: &str,
    ) -> io::Result<(kyber1024::PublicKey, kyber1024::SecretKey)> {
        let pk_data = std::fs::read(pub_path)?;
        let sk_data = std::fs::read(sec_path)?;

        let pk_bytes = Base64Engine
            .decode(&pk_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let sk_bytes = Base64Engine
            .decode(&sk_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let pk = kyber1024::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let sk = kyber1024::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok((pk, sk))
    }

    pub fn load_dilithium_keys(
        pub_path: &str,
        sec_path: &str,
    ) -> io::Result<(dilithium5::PublicKey, dilithium5::SecretKey)> {
        let pk_data = std::fs::read(pub_path)?;
        let sk_data = std::fs::read(sec_path)?;

        let pk_bytes = Base64Engine
            .decode(&pk_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let sk_bytes = Base64Engine
            .decode(&sk_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let pk = dilithium5::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let sk = dilithium5::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok((pk, sk))
    }
}
