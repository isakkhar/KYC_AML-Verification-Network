use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn};
use uuid::Uuid;

use crate::models::{
    user::User,
    verification::{VerificationRequest, VerificationStatus},
    attestation::Attestation,
};
use crate::kyc::{
    verification::KycVerifier,
    token::KycToken,
    attestation::AttestationService,
};
use crate::AppState;
use crate::utils::error::AppError;

#[derive(Deserialize)]
pub struct SubmitKycRequest {
    pub user_id: Uuid,
    pub document_type: String,
    pub document_data: String, // Base64 encoded document
    pub personal_info: PersonalInfo,
}

#[derive(Deserialize, Serialize)]
pub struct PersonalInfo {
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: String,
    pub nationality: String,
    pub address: String,
}

#[derive(Serialize)]
pub struct KycSubmissionResponse {
    pub verification_id: Uuid,
    pub status: String,
    pub message: String,
    pub estimated_completion: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct KycVerificationResponse {
    pub valid: bool,
    pub user_id: Uuid,
    pub verification_level: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub attestations: Vec<String>,
}

#[derive(Deserialize)]
pub struct AttestationRequest {
    pub user_id: Uuid,
    pub verifier_id: String,
    pub attestation_type: String,
    pub data: serde_json::Value,
}

#[derive(Serialize)]
pub struct AttestationResponse {
    pub attestation_id: Uuid,
    pub signature: String,
    pub blockchain_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub user_id: Uuid,
    pub status: String,
    pub verification_level: Option<String>,
    pub kyc_token: Option<String>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub attestations: Vec<AttestationSummary>,
}

#[derive(Serialize)]
pub struct AttestationSummary {
    pub id: Uuid,
    pub type_: String,
    pub verifier: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

/// Submit KYC documents for verification
pub async fn submit_kyc(
    data: web::Data<AppState>,
    req: web::Json<SubmitKycRequest>,
) -> Result<HttpResponse, AppError> {
    info!("Received KYC submission for user: {}", req.user_id);

    // Validate request
    if req.document_data.is_empty() {
        warn!("Empty document data received for user: {}", req.user_id);
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Document data is required"
        })));
    }

    // Create verification request
    let verification_request = VerificationRequest {
        id: Uuid::new_v4(),
        user_id: req.user_id,
        document_type: req.document_type.clone(),
        document_hash: format!("hash_{}", req.user_id), // In real implementation, hash the document
        personal_info_hash: format!("info_hash_{}", req.user_id),
        status: VerificationStatus::Pending,
        submitted_at: chrono::Utc::now(),
        processed_at: None,
        expires_at: chrono::Utc::now() + chrono::Duration::days(30),
    };

    // Store in database
    let query = r#"
        INSERT INTO verification_requests (
            id, user_id, document_type, document_hash, personal_info_hash,
            status, submitted_at, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    "#;

    sqlx::query(query)
        .bind(verification_request.id)
        .bind(verification_request.user_id)
        .bind(&verification_request.document_type)
        .bind(&verification_request.document_hash)
        .bind(&verification_request.personal_info_hash)
        .bind("pending")
        .bind(verification_request.submitted_at)
        .bind(verification_request.expires_at)
        .execute(&data.db_pool)
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            AppError::DatabaseError(e.to_string())
        })?;

    // Initialize KYC verifier
    let verifier = KycVerifier::new(
        data.substrate_client.clone(),
        data.db_pool.clone(),
    );

    // Start async verification process
    let verification_id = verification_request.id;
    let user_id = req.user_id;
    let document_data = req.document_data.clone();
    let personal_info = req.personal_info.clone();

    tokio::spawn(async move {
        match verifier.verify_documents(user_id, &document_data, &personal_info).await {
            Ok(_) => {
                info!("KYC verification completed successfully for user: {}", user_id);
            }
            Err(e) => {
                error!("KYC verification failed for user {}: {}", user_id, e);
            }
        }
    });

    let response = KycSubmissionResponse {
        verification_id,
        status: "submitted".to_string(),
        message: "KYC verification started. You will be notified when complete.".to_string(),
        estimated_completion: chrono::Utc::now() + chrono::Duration::minutes(30),
    };

    info!("KYC submission processed for user: {}", req.user_id);
    Ok(HttpResponse::Ok().json(response))
}

/// Verify a KYC token
pub async fn verify_kyc_token(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();
    info!("Verifying KYC token: {}", token);

    // Validate token
    let kyc_token = KycToken::verify(&token, &data.settings.jwt.secret)
        .map_err(|e| {
            warn!("Invalid KYC token: {}", e);
            AppError::ValidationError(e.to_string())
        })?;

    // Check if token is still valid
    if kyc_token.is_expired() {
        warn!("Expired KYC token: {}", token);
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Token expired"
        })));
    }

    // Fetch user verification status
    let query = r#"
        SELECT status, verification_level, created_at, expires_at
        FROM user_verifications
        WHERE user_id = $1 AND status = 'verified'
    "#;

    let row = sqlx::query(query)
        .bind(kyc_token.user_id)
        .fetch_optional(&data.db_pool)
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            AppError::DatabaseError(e.to_string())
        })?;

    if let Some(row) = row {
        let verification_level: String = row.try_get("verification_level")?;
        let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
        let expires_at: chrono::DateTime<chrono::Utc> = row.try_get("expires_at")?;

        // Fetch attestations
        let attestations_query = r#"
            SELECT verifier_id FROM attestations
            WHERE user_id = $1 AND status = 'active'
        "#;

        let attestations: Vec<String> = sqlx::query_scalar(attestations_query)
            .bind(kyc_token.user_id)
            .fetch_all(&data.db_pool)
            .await
            .map_err(|e| {
                error!("Database error fetching attestations: {}", e);
                AppError::DatabaseError(e.to_string())
            })?;

        let response = KycVerificationResponse {
            valid: true,
            user_id: kyc_token.user_id,
            verification_level,
            issued_at: created_at,
            expires_at,
            attestations,
        };

        info!("KYC token verified successfully for user: {}", kyc_token.user_id);
        Ok(HttpResponse::Ok().json(response))
    } else {
        warn!("No valid verification found for user: {}", kyc_token.user_id);
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "No valid verification found"
        })))
    }
}

/// Create an attestation
pub async fn create_attestation(
    data: web::Data<AppState>,
    req: web::Json<AttestationRequest>,
) -> Result<HttpResponse, AppError> {
    info!("Creating attestation for user: {}", req.user_id);

    let attestation_service = AttestationService::new(
        data.substrate_client.clone(),
        data.db_pool.clone(),
    );

    let attestation_id = attestation_service
        .create_attestation(
            req.user_id,
            &req.verifier_id,
            &req.attestation_type,
            &req.data,
        )
        .await
        .map_err(|e| {
            error!("Failed to create attestation: {}", e);
            AppError::AttestationError(e.to_string())
        })?;

    // Store on blockchain
    let blockchain_hash = data.substrate_client
        .store_attestation(attestation_id, &req.data)
        .await
        .map_err(|e| {
            error!("Failed to store attestation on blockchain: {}", e);
            AppError::BlockchainError(e.to_string())
        })?;

    // Generate signature
    let signature = format!("sig_{}", attestation_id);

    let response = AttestationResponse {
        attestation_id,
        signature,
        blockchain_hash,
        timestamp: chrono::Utc::now(),
    };

    info!("Attestation created successfully: {}", attestation_id);
    Ok(HttpResponse::Created().json(response))
}

/// Get verification status for a user
pub async fn get_verification_status(
    data: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let user_id = path.into_inner();
    info!("Fetching verification status for user: {}", user_id);

    // Get verification status
    let verification_query = r#"
        SELECT status, verification_level, updated_at, kyc_token
        FROM user_verifications
        WHERE user_id = $1
        ORDER BY updated_at DESC
        LIMIT 1
    "#;

    let verification_row = sqlx::query(verification_query)
        .bind(user_id)
        .fetch_optional(&data.db_pool)
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            AppError::DatabaseError(e.to_string())
        })?;

    if let Some(row) = verification_row {
        let status: String = row.try_get("status")?;
        let verification_level: Option<String> = row.try_get("verification_level")?;
        let updated_at: chrono::DateTime<chrono::Utc> = row.try_get("updated_at")?;
        let kyc_token: Option<String> = row.try_get("kyc_token")?;

        // Get attestations
        let attestations_query = r#"
            SELECT id, attestation_type, verifier_id, created_at, status
            FROM attestations
            WHERE user_id = $1
            ORDER BY created_at DESC
        "#;

        let attestation_rows = sqlx::query(attestations_query)
            .bind(user_id)
            .fetch_all(&data.db_pool)
            .await
            .map_err(|e| {
                error!("Database error fetching attestations: {}", e);
                AppError::DatabaseError(e.to_string())
            })?;

        let attestations: Vec<AttestationSummary> = attestation_rows
            .into_iter()
            .map(|row| AttestationSummary {
                id: row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
                type_: row.try_get("attestation_type").unwrap_or_default(),
                verifier: row.try_get("verifier_id").unwrap_or_default(),
                timestamp: row.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now()),
                status: row.try_get("status").unwrap_or_default(),
            })
            .collect();

        let response = StatusResponse {
            user_id,
            status,
            verification_level,
            kyc_token,
            last_updated: updated_at,
            attestations,
        };

        info!("Verification status retrieved for user: {}", user_id);
        Ok(HttpResponse::Ok().json(response))
    } else {
        warn!("No verification found for user: {}", user_id);
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "No verification found for user"
        })))
    }
}