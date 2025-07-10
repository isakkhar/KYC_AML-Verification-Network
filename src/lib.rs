pub mod api;
pub mod blockchain;
pub mod kyc;
pub mod crypto;
pub mod external;
pub mod models;
pub mod config;
pub mod utils;

pub use crate::utils::error::AppError;
pub use crate::config::Settings;

// Re-export commonly used types
pub use crate::models::{
    user::User,
    verification::VerificationRequest,
    attestation::Attestation,
};

pub use crate::kyc::{
    verification::KycVerifier,
    token::KycToken,
    attestation::AttestationService,
};

pub use crate::blockchain::SubstrateClient;
pub use crate::crypto::{
    encryption::Encryptor,
    signatures::Signer,
};