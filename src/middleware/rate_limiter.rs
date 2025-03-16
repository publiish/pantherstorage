use crate::services::rate_limiter::RateLimiter;
use actix_service::{Service, Transform};
use actix_web::error::Error as ActixError;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::task::{Context, Poll};

/// Middleware implementing rate limiting for Actix-web
pub struct RateLimiterMiddleware<S> {
    service: S,
    rate_limiter: RateLimiter,
}

impl<S> RateLimiterMiddleware<S> {
    #[allow(dead_code)]
    pub fn new(service: S, rate_limiter: RateLimiter) -> Self {
        RateLimiterMiddleware {
            service,
            rate_limiter,
        }
    }
}

impl<S, B> Transform<S, actix_web::dev::ServiceRequest> for RateLimiter
where
    S: Service<
            actix_web::dev::ServiceRequest,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = ActixError,
        > + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = RateLimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimiterMiddleware {
            service,
            rate_limiter: self.clone(),
        })
    }
}

impl<S, B> Service<actix_web::dev::ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<
            actix_web::dev::ServiceRequest,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = ActixError,
        > + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: actix_web::dev::ServiceRequest) -> Self::Future {
        let ip = req
            .peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match self.rate_limiter.check_rate_limit(&ip) {
            Ok(()) => {
                let fut = self.service.call(req);
                Box::pin(async move { fut.await })
            }
            Err(e) => Box::pin(async move { Err(e.into()) }),
        }
    }
}
