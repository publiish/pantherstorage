use serde::Deserialize;
use validator::{Validate, ValidationError};

/// Request structure for user signup
///
/// # Examples
///
/// ```rust
/// let request = SignupRequest {
///     username: "publiish".to_string(),
///     email: "publiish@example.com".to_string(),
///     password: "Passw0rd123!".to_string(),
/// };
/// ```
#[derive(Debug, Validate, Deserialize)]
pub struct SignupRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    #[validate(custom(function = "validate_password"))]
    pub password: String,
}

/// Request structure for user signin
///
/// # Examples
///
/// ```rust
/// let request = SigninRequest {
///     email: "publiish@example.com".to_string(),
///     password: "Passw0rd123!".to_string(),
/// };
/// ```
#[derive(Debug, Validate, Deserialize)]
pub struct SigninRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

/// Validates password complexity requirements
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if !password.chars().any(char::is_uppercase)
        || !password.chars().any(char::is_numeric)
        || !password.chars().any(|c| "!@#$%^&*".contains(c))
    {
        return Err(ValidationError::new(
            "Password must contain at least one uppercase letter, one number, and one special character",
        ));
    }
    Ok(())
}

/// Request structure for uploading files
#[derive(Debug, Validate, Deserialize)]
pub struct UploadRequest {
    #[validate(length(min = 1, max = 255))]
    pub file_path: String,
}

/// Request structure for downloading files
#[derive(Debug, Validate, Deserialize)]
pub struct DownloadRequest {
    #[validate(length(min = 1))]
    pub cid: String,
    #[validate(length(min = 1, max = 255))]
    pub output_path: String,
}

/// Request structure for deleting files
#[derive(Debug, Validate, Deserialize)]
pub struct DeleteRequest {
    #[validate(length(min = 1))]
    pub cid: String,
}
