use actix_web::{web, HttpResponse};
use serde_json::json;

use crate::api::handlers;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/kyc")
            .route("/submit", web::post().to(handlers::submit_kyc))
            .route("/verify/{token}", web::get().to(handlers::verify_kyc_token))
            .route("/attest", web::post().to(handlers::create_attestation))
            .route("/status/{user_id}", web::get().to(handlers::get_verification_status))
    )
        .service(
            web::scope("/admin")
                .route("/stats", web::get().to(admin_stats))
                .route("/users", web::get().to(list_users))
                .route("/verifications", web::get().to(list_verifications))
        )
        .service(
            web::scope("/webhook")
                .route("/external-verifier", web::post().to(external_verifier_webhook))
                .route("/bank-verification", web::post().to(bank_verification_webhook))
        );
}

/// Get admin statistics
async fn admin_stats() -> actix_web::Result<HttpResponse> {
    // In a real implementation, this would query the database for actual stats
    Ok(HttpResponse::Ok().json(json!({
        "total_users": 1250,
        "verified_users": 987,
        "pending_verifications": 45,
        "active_attestations": 892,
        "total_attestations": 1034,
        "success_rate": 0.923,
        "avg_verification_time_minutes": 18.5,
        "blockchain_transactions": 1876,
        "last_updated": chrono::Utc::now().to_rfc3339()
    })))
}

/// List users (admin only)
async fn list_users() -> actix_web::Result<HttpResponse> {
    // In a real implementation, this would query the database with pagination
    Ok(HttpResponse::Ok().json(json!({
        "users": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "verified",
                "verification_level": "enhanced",
                "created_at": "2024-01-15T10:30:00Z",
                "last_activity": "2024-01-20T14:22:00Z"
            },
            {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "status": "pending",
                "verification_level": null,
                "created_at": "2024-01-20T09:15:00Z",
                "last_activity": "2024-01-20T09:15:00Z"
            }
        ],
        "total": 1250,
        "page": 1,
        "limit": 50
    })))
}

/// List verifications (admin only)
async fn list_verifications() -> actix_web::Result<HttpResponse> {
    // In a real implementation, this would query the database with pagination
    Ok(HttpResponse::Ok().json(json!({
        "verifications": [
            {
                "id": "650e8400-e29b-41d4-a716-446655440000",
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "verified",
                "document_type": "passport",
                "verification_level": "enhanced",
                "submitted_at": "2024-01-15T10:30:00Z",
                "processed_at": "2024-01-15T10:48:00Z",
                "processing_time_minutes": 18
            },
            {
                "id": "650e8400-e29b-41d4-a716-446655440001",
                "user_id": "550e8400-e29b-41d4-a716-446655440001",
                "status": "pending",
                "document_type": "drivers_license",
                "verification_level": null,
                "submitted_at": "2024-01-20T09:15:00Z",
                "processed_at": null,
                "processing_time_minutes": null
            }
        ],
        "total": 1295,
        "page": 1,
        "limit": 50
    })))
}

/// Webhook for external verifier notifications
async fn external_verifier_webhook() -> actix_web::Result<HttpResponse> {
    // In a real implementation, this would process webhook data from external verifiers
    Ok(HttpResponse::Ok().json(json!({
        "status": "received",
        "message": "Webhook processed successfully"
    })))
}

/// Webhook for bank verification notifications
async fn bank_verification_webhook() -> actix_web::Result<HttpResponse> {
    // In a real implementation, this would process webhook data from banks
    Ok(HttpResponse::Ok().json(json!({
        "status": "received",
        "message": "Bank verification webhook processed"
    })))
}