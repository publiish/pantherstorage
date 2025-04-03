use crate::errors::ServiceError;
use crate::routes::AppState;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error as ActixError,
};
use dashmap::DashMap;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use governor::{
    clock::QuantaClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    RateLimiter as GovernorRateLimiter,
};
use log;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const REQUESTS_PER_MINUTE: u32 = 100;
const BURST_SIZE: u32 = 10;

#[derive(Clone)]
pub struct RateLimiterEntry {
    pub limiter: Arc<GovernorRateLimiter<NotKeyed, InMemoryState, QuantaClock, NoOpMiddleware>>,
    pub last_used: Instant,
}

/// Per-user rate limiting middleware
pub struct UserRateLimiterMiddleware<S> {
    service: S,
    rate_limiters: Arc<DashMap<String, RateLimiterEntry>>,
}

/// Rate limiter initializer
#[derive(Clone)]
pub struct UserRateLimiter;

impl UserRateLimiter {
    pub fn new() -> Self {
        UserRateLimiter
    }
}

impl<S> UserRateLimiterMiddleware<S> {
    pub fn new(service: S) -> Self {
        let middleware = UserRateLimiterMiddleware {
            service,
            rate_limiters: Arc::new(DashMap::new()),
        };

        // Start the cleanup task
        let rate_limiters = middleware.rate_limiters.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                perform_cleanup(rate_limiters.clone()).await;
            }
        });

        middleware
    }
}

impl<S, B> Transform<S, ServiceRequest> for UserRateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = UserRateLimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(UserRateLimiterMiddleware::new(service))
    }
}

impl<S, B> Service<ServiceRequest> for UserRateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract user ID from token if available, otherwise use IP
        let user_id = req
            .headers()
            .get("Authorization")
            .and_then(|token| {
                let token = token.to_str().ok()?.strip_prefix("Bearer ")?;
                let app_state = req.app_data::<actix_web::web::Data<AppState>>()?;
                app_state
                    .ipfs_service
                    .verify_token(token)
                    .ok()
                    .map(|claims| claims.sub)
            })
            .unwrap_or_else(|| {
                req.peer_addr()
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            });

        // Get or create rate limiter for this user
        let mut entry = self
            .rate_limiters
            .entry(user_id.clone())
            .or_insert_with(|| RateLimiterEntry {
                limiter: Arc::new(GovernorRateLimiter::direct_with_clock(
                    governor::Quota::per_minute(NonZeroU32::new(REQUESTS_PER_MINUTE).unwrap())
                        .allow_burst(NonZeroU32::new(BURST_SIZE).unwrap()),
                    QuantaClock::default(),
                )),
                last_used: Instant::now(),
            });

        // Update last used time and get the limiter
        entry.value_mut().last_used = Instant::now();
        let limiter = entry.value().limiter.clone();
        // Explicitly drop the entry to release the lock
        drop(entry);

        // Check rate limit
        if limiter.check().is_err() {
            return Box::pin(async move { Err(ServiceError::RateLimit.into()) });
        }

        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}

async fn perform_cleanup(rate_limiters: Arc<DashMap<String, RateLimiterEntry>>) {
    let initial_count = rate_limiters.len();
    let expiry_threshold = Duration::from_secs(3600);
    let now = Instant::now();

    // Remove expired entries
    rate_limiters.retain(|_, entry| now.duration_since(entry.last_used) < expiry_threshold);

    let current_count = rate_limiters.len();
    let removed = initial_count - current_count;

    if removed > 0 {
        log::info!(
            "Cleaned up rate limiters. Removed: {}, Remaining: {}",
            removed,
            current_count
        );
    }
}

pub async fn cleanup_rate_limiters(rate_limiters: Arc<DashMap<String, RateLimiterEntry>>) {
    perform_cleanup(rate_limiters).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        dev::{Service, ServiceRequest},
        http::{header, StatusCode},
        test::TestRequest,
        HttpResponse,
    };
    use futures_util::future::LocalBoxFuture;
    use governor::Quota;
    use std::time::Duration;
    use tokio::time::sleep;

    // Mock service for testing
    struct MockService;
    impl Service<ServiceRequest> for MockService {
        type Response = ServiceResponse;
        type Error = ActixError;
        type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&self, req: ServiceRequest) -> Self::Future {
            let fut = async move { Ok(req.into_response(HttpResponse::Ok().body("Success"))) };
            Box::pin(fut)
        }
    }

    // Helper to create a test request
    fn create_test_request(user_id: Option<&str>) -> ServiceRequest {
        let mut req = TestRequest::get().uri("/test");
        if let Some(id) = user_id {
            req = req.insert_header((header::AUTHORIZATION, format!("Bearer {}", id)));
        }
        // Simulate different IPs for different users
        let req = match user_id {
            Some("user1") => req.peer_addr("1.1.1.1:8081".parse().unwrap()),
            Some("user2") => req.peer_addr("2.2.2.2:8081".parse().unwrap()),
            _ => req.peer_addr("0.0.0.0:8081".parse().unwrap()),
        };
        req.to_srv_request()
    }

    #[tokio::test]
    async fn test_rate_limiter_initial_request() {
        let limiter = UserRateLimiterMiddleware::new(MockService);
        let req = create_test_request(Some("user1"));

        let resp = limiter.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rate_limiter_burst_limit() {
        let limiter = UserRateLimiterMiddleware::new(MockService);

        // Test burst limit (10 requests)
        for _ in 0..BURST_SIZE {
            let req = create_test_request(Some("user1"));
            let resp = limiter.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // 11th request should be rate limited
        let req = create_test_request(Some("user1"));
        let resp = limiter.call(req).await;
        assert!(resp.is_err());
        let err = resp.unwrap_err();
        assert_eq!(err.to_string(), ServiceError::RateLimit.to_string());
    }

    #[tokio::test]
    async fn test_rate_limiter_per_minute_quota() {
        let limiter = UserRateLimiterMiddleware::new(MockService);

        // Exhaust burst (10 requests)
        for i in 0..BURST_SIZE {
            let req = create_test_request(Some("user2"));
            let resp = limiter.call(req).await.unwrap();
            println!("Request {}: {:?}", i + 1, resp.status());
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Wait a very short time (100ms) to minimize replenishment
        sleep(Duration::from_millis(100)).await;
        let req = create_test_request(Some("user2"));
        let resp = limiter.call(req).await;
        println!("After 100ms wait: {:?}", resp);
        // Should be rate limited
        assert!(resp.is_err(), "Expected rate limit error, got {:?}", resp);

        // Wait for full replenishment (60 seconds total)
        sleep(Duration::from_secs(60)).await;
        let req = create_test_request(Some("user2"));
        let resp = limiter.call(req).await.unwrap();
        println!("After 60s wait: {:?}", resp.status());
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_different_users_independent_limits() {
        let limiter = UserRateLimiterMiddleware::new(MockService);

        // Exhaust limit for user1
        for _ in 0..BURST_SIZE {
            let req = create_test_request(Some("user1"));
            let resp = limiter.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let req = create_test_request(Some("user1"));
        let resp = limiter.call(req).await;
        assert!(resp.is_err());

        // User2 should still have full quota
        for _ in 0..BURST_SIZE {
            let req = create_test_request(Some("user2"));
            let resp = limiter.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_unauthenticated_user_ip_fallback() {
        let limiter = UserRateLimiterMiddleware::new(MockService);

        // Request without auth header (uses IP)
        let req = create_test_request(None);
        let resp = limiter.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Exhaust burst for "unknown" IP
        for _ in 0..BURST_SIZE - 1 {
            // -1 because we already made one request
            let req = create_test_request(None);
            let resp = limiter.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let req = create_test_request(None);
        let resp = limiter.call(req).await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_cleanup() {
        let rate_limiters = Arc::new(DashMap::new());
        let user_id = "test_user".to_string();

        // Add a rate limiter with an old timestamp
        rate_limiters.insert(
            user_id.clone(),
            RateLimiterEntry {
                limiter: Arc::new(GovernorRateLimiter::direct_with_clock(
                    Quota::per_minute(NonZeroU32::new(REQUESTS_PER_MINUTE).unwrap())
                        .allow_burst(NonZeroU32::new(BURST_SIZE).unwrap()),
                    QuantaClock::default(),
                )),
                // Set last_used to 2 hours ago to ensure it exceeds the 1-hour threshold
                last_used: Instant::now() - Duration::from_secs(7200),
            },
        );

        assert_eq!(rate_limiters.len(), 1);
        cleanup_rate_limiters(rate_limiters.clone()).await;
        assert_eq!(rate_limiters.len(), 0);
    }
}
