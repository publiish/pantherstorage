use serde::{Deserialize, Serialize};

/// JWT claims for authentication tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

/// Response containing authentication token
#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}
