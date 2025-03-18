use crate::errors::ServiceError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Implements rate limiting for API requests
///
/// # Examples
/// // 100 requests per minute
/// ```rust
/// let limiter = RateLimiter::new(100, 60);
/// ```
#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, (u64, u32)>>>,
    max_requests: u32,
    interval: u64,
}

impl RateLimiter {
    /// Creates a new rate limiter
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum number of requests allowed in the interval
    /// * `interval` - Time window in seconds
    pub fn new(max_requests: u32, interval: u64) -> Self {
        RateLimiter {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            interval,
        }
    }

    pub fn check_rate_limit(&self, ip: &str) -> Result<(), ServiceError> {
        let mut requests = self
            .requests
            .lock()
            .map_err(|e| ServiceError::Internal(format!("Mutex lock failed: {}", e)))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = requests.entry(ip.to_string()).or_insert((now, 0));
        if now - entry.0 >= self.interval {
            *entry = (now, 1);
        } else if entry.1 >= self.max_requests {
            return Err(ServiceError::RateLimit);
        } else {
            entry.1 += 1;
        }
        Ok(())
    }
}
