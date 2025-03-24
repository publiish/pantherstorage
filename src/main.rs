use actix_web::{middleware as actix_middleware, App, HttpServer};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use clap::{Parser, Subcommand};
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
    /// cargo run -- generate-keys --base64
    /// cargo run -- generate-keys --output /path/to/keys --base64
    GenerateKeys {
        /// Output directory for keys (default: current directory)
        #[arg(short, long, default_value = ".")]
        output: String,
        /// Output keys in Base64 format instead of binary
        #[arg(long)]
        base64: bool,
    },
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::GenerateKeys { output, base64 }) => {
            generate_keys(&output, base64)?;
            Ok(())
        }
        None => start_server().await,
    }
}

fn generate_keys(output_dir: &str, use_base64: bool) -> io::Result<()> {
    // Generate Kyber1024 KEM keys
    let (pk_kem, sk_kem) = kyber1024::keypair();
    // Generate Dilithium5 signature keys
    let (pk_sign, sk_sign) = dilithium5::keypair();

    if use_base64 {
        // Convert to Base64
        let pk_kem_b64 = Base64Engine.encode(pk_kem.as_bytes());
        let sk_kem_b64 = Base64Engine.encode(sk_kem.as_bytes());
        let pk_sign_b64 = Base64Engine.encode(pk_sign.as_bytes());
        let sk_sign_b64 = Base64Engine.encode(sk_sign.as_bytes());

        // Save Base64 encoded keys
        std::fs::write(format!("{}/kyber1024_public.key", output_dir), pk_kem_b64)?;
        std::fs::write(format!("{}/kyber1024_secret.key", output_dir), sk_kem_b64)?;
        std::fs::write(format!("{}/dilithium5_public.key", output_dir), pk_sign_b64)?;
        std::fs::write(format!("{}/dilithium5_secret.key", output_dir), sk_sign_b64)?;

        println!(
            "Base64-encoded keys generated successfully in {}:",
            output_dir
        );
    } else {
        // Save raw binary keys
        std::fs::write(
            format!("{}/kyber1024_public.key", output_dir),
            pk_kem.as_bytes(),
        )?;
        std::fs::write(
            format!("{}/kyber1024_secret.key", output_dir),
            sk_kem.as_bytes(),
        )?;
        std::fs::write(
            format!("{}/dilithium5_public.key", output_dir),
            pk_sign.as_bytes(),
        )?;
        std::fs::write(
            format!("{}/dilithium5_secret.key", output_dir),
            sk_sign.as_bytes(),
        )?;

        println!("Binary keys generated successfully in {}:", output_dir);
    }

    println!("- kyber1024_public.key (KEM public key)");
    println!("- kyber1024_secret.key (KEM secret key)");
    println!("- dilithium5_public.key (Signature public key)");
    println!("- dilithium5_secret.key (Signature secret key)");

    Ok(())
}

async fn start_server() -> io::Result<()> {
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

pub mod crypto_utils {
    use super::*;

    pub fn load_kyber_keys(
        pub_path: &str,
        sec_path: &str,
        is_base64: bool,
    ) -> io::Result<(kyber1024::PublicKey, kyber1024::SecretKey)> {
        let pk_data = std::fs::read(pub_path)?;
        let sk_data = std::fs::read(sec_path)?;

        let (pk_bytes, sk_bytes) = if is_base64 {
            (
                Base64Engine
                    .decode(&pk_data)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                Base64Engine
                    .decode(&sk_data)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            )
        } else {
            (pk_data, sk_data)
        };

        let pk = kyber1024::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let sk = kyber1024::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok((pk, sk))
    }

    pub fn load_dilithium_keys(
        pub_path: &str,
        sec_path: &str,
        is_base64: bool,
    ) -> io::Result<(dilithium5::PublicKey, dilithium5::SecretKey)> {
        let pk_data = std::fs::read(pub_path)?;
        let sk_data = std::fs::read(sec_path)?;

        let (pk_bytes, sk_bytes) = if is_base64 {
            (
                Base64Engine
                    .decode(&pk_data)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                Base64Engine
                    .decode(&sk_data)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            )
        } else {
            (pk_data, sk_data)
        };

        let pk = dilithium5::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let sk = dilithium5::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok((pk, sk))
    }
}
