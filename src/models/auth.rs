use serde::{Deserialize, Serialize};

/// Post-Quantum Safe Auth Token Header.
#[derive(Serialize, Deserialize)]
pub struct TokenHeader {
    pub alg: String,
    pub typ: String,
    pub nonce: String,
}

/// PQS Token Claims
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

/// Auth Response containing PQS token
#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}
