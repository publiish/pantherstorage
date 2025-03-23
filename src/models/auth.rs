use serde::{Deserialize, Serialize};

/// POC Token Header
#[derive(Serialize, Deserialize)]
pub struct TokenHeader {
    pub alg: String,
    pub typ: String,
    pub nonce: String,
}

/// PQC Claims for authentication tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    // PQC signature
    pub signature: Vec<u8>,
    // Issued at timestamp
    pub iat: usize,
    pub nonce: String,
}

/// Response containing authentication token
#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}
