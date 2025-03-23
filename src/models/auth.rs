use serde::{Deserialize, Serialize};

/// PQC Claims for authentication tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    // PQC signature
    pub signature: Vec<u8>,
}

/// Response containing authentication token
#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}
