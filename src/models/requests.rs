use serde::Deserialize;
use validator::{Validate, ValidationError};

/// Request structure for user signup
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

/// Request structure for deleting files
#[derive(Debug, Validate, Deserialize)]
pub struct DeleteRequest {
    #[validate(length(min = 1))]
    pub cid: String,
}
