use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};
use tracing::{info, warn};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

pub struct AuthMiddleware {
    pub secret: String,
}

impl AuthMiddleware {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service,
            secret: self.secret.clone(),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
    secret: String,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let secret = self.secret.clone();

        Box::pin(async move {
            // Skip authentication for health check and public endpoints
            let path = req.path();
            if path.starts_with("/health") || path.starts_with("/api/v1/kyc/verify") {
                return service.call(req).await;
            }

            // Check for Authorization header
            if let Some(auth_header) = req.headers().get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = &auth_str[7..];

                        // Validate JWT token
                        let validation = Validation::new(Algorithm::HS256);
                        let decoding_key = DecodingKey::from_secret(secret.as_ref());

                        match decode::<Claims>(token, &decoding_key, &validation) {
                            Ok(token_data) => {
                                // Add user info to request extensions
                                req.extensions_mut().insert(token_data.claims);
                                info!("Authenticated user: {}", token_data.claims.sub);
                                return service.call(req).await;
                            }
                            Err(e) => {
                                warn!("Invalid JWT token: {}", e);
                            }
                        }
                    }
                }
            }

            // Check for API key (alternative authentication method)
            if let Some(api_key) = req.headers().get("X-API-Key") {
                if let Ok(key_str) = api_key.to_str() {
                    // In a real implementation, validate API key against database
                    if is_valid_api_key(key_str).await {
                        info!("Authenticated via API key");
                        return service.call(req).await;
                    }
                }
            }

            // Authentication failed
            warn!("Authentication failed for path: {}", path);
            let response = HttpResponse::Unauthorized()
                .json(serde_json::json!({
                    "error": "Authentication required",
                    "message": "Please provide a valid Bearer token or API key"
                }));

            Ok(req.into_response(response))
        })
    }
}

async fn is_valid_api_key(api_key: &str) -> bool {
    // In a real implementation, this would check against a database
    // For demo purposes, we'll accept a hardcoded key
    api_key == "kyc-demo-api-key-12345"
}

// Rate limiting middleware
pub struct RateLimitMiddleware {
    pub requests_per_minute: u32,
}

impl RateLimitMiddleware {
    pub fn new(requests_per_minute: u32) -> Self {
        Self { requests_per_minute }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddlewareService {
            service,
            requests_per_minute: self.requests_per_minute,
        }))
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: S,
    requests_per_minute: u32,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            // In a real implementation, this would check rate limits per IP/user
            // For demo purposes, we'll just log and pass through
            let client_ip = req.connection_info().peer_addr().unwrap_or("unknown");
            info!("Rate limit check for IP: {}", client_ip);

            service.call(req).await
        })
    }
}

// Convenience function to create auth middleware
pub fn auth_middleware() -> AuthMiddleware {
    AuthMiddleware::new("your-secret-key-here".to_string())
}

// Security headers middleware
pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddlewareService { service }))
    }
}

pub struct SecurityHeadersMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            let mut res = service.call(req).await?;

            // Add security headers
            let headers = res.headers_mut();
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-content-type-options"),
                actix_web::http::header::HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-frame-options"),
                actix_web::http::header::HeaderValue::from_static("DENY"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-xss-protection"),
                actix_web::http::header::HeaderValue::from_static("1; mode=block"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("strict-transport-security"),
                actix_web::http::header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );

            Ok(res)
        })
    }
}