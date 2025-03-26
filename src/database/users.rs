use crate::errors::ServiceError;
use crate::models::requests::{SigninRequest, SignupRequest};
use crate::utils::{hash_password, verify_password};
use log::info;
use mysql_async::{prelude::*, Pool};
use validator::Validate;

/// Creates a new user in the database
pub async fn create_user(
    db_pool: &Pool,
    username: &str,
    email: &str,
    password_hash: &str,
) -> Result<i32, ServiceError> {
    let mut conn = db_pool.get_conn().await?;
    let result = conn
        .exec_drop(
            "INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)",
            params! {
                "username" => username,
                "email" => email,
                "password_hash" => password_hash,
            },
        )
        .await;

    if let Err(mysql_async::Error::Server(err)) = &result {
        if err.code == 1062 {
            return Err(ServiceError::InvalidInput(
                "Username or email already exists".to_string(),
            ));
        }
    }
    result?;

    let user_id: i32 = conn
        .query_first("SELECT LAST_INSERT_ID()")
        .await?
        .ok_or_else(|| ServiceError::Internal("Failed to get user ID".to_string()))?;

    Ok(user_id)
}

/// Authenticates a user and returns their ID and password hash
pub async fn authenticate_user(db_pool: &Pool, email: &str) -> Result<(i32, String), ServiceError> {
    let mut conn = db_pool.get_conn().await?;
    let user: Option<(i32, String)> = conn
        .exec_first(
            "SELECT id, password_hash FROM users WHERE email = :email",
            params! { "email" => email },
        )
        .await?;

    let (user_id, password_hash) =
        user.ok_or(ServiceError::Auth("Invalid credentials".to_string()))?;

    Ok((user_id, password_hash))
}

/// Registers a new user and returns their ID
pub async fn register_user(db_pool: &Pool, req: &SignupRequest) -> Result<i32, ServiceError> {
    req.validate()
        .map_err(|e| ServiceError::Validation(e.to_string()))?;

    let password_hash = hash_password(&req.password)?;
    let user_id = create_user(db_pool, &req.username, &req.email, &password_hash).await?;

    info!("New user registered: {}", req.email);
    Ok(user_id)
}

/// Authenticates a user and returns their ID if credentials are valid
pub async fn login_user(db_pool: &Pool, req: &SigninRequest) -> Result<i32, ServiceError> {
    req.validate()
        .map_err(|e| ServiceError::Validation(e.to_string()))?;

    let (user_id, password_hash) = authenticate_user(db_pool, &req.email).await?;

    if !verify_password(&req.password, &password_hash)? {
        return Err(ServiceError::Auth("Invalid credentials".to_string()));
    }

    Ok(user_id)
}
