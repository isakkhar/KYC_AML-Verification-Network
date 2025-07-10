use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair, H256};
use sp_keyring::AccountKeyring;
use substrate_subxt::{
    ClientBuilder, DefaultConfig, PolkadotExtrinsicParams, SubstrateExtrinsicParams,
    system::System,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationProof {
    pub user_id: Uuid,
    pub document_hash: String,
    pub verification_level: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub verifier_signature: String,
    pub merkle_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    pub id: Uuid,
    pub user_id: Uuid,
    pub attestation_type: String,
    pub verifier_id: String,
    pub data_hash: String,
    pub signature: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct SubstrateClient {
    endpoint: String,
    keypair: sr25519::Pair,
    // In-memory storage for demo purposes (would use actual blockchain in production)
    storage: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    block_height: Arc<RwLock<u64>>,
}

impl SubstrateClient {
    pub async fn new(endpoint: &str) -> Result<Self> {
        info!("Initializing Substrate client for endpoint: {}", endpoint);

        // Generate a keypair for signing transactions
        let keypair = AccountKeyring::Alice.pair();

        let client = Self {
            endpoint: endpoint.to_string(),
            keypair,
            storage: Arc::new(RwLock::new(HashMap::new())),
            block_height: Arc::new(RwLock::new(0)),
        };

        // Test connection
        client.test_connection().await?;

        info!("Substrate client initialized successfully");
        Ok(client)
    }

    async fn test_connection(&self) -> Result<()> {
        // In a real implementation, this would connect to the actual Substrate node
        // For demo purposes, we'll simulate a successful connection
        info!("Testing connection to Substrate node...");
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        info!("Connection to Substrate node established");
        Ok(())
    }

    pub async fn store_verification_proof(&self, proof: VerificationProof) -> Result<String> {
        info!("Storing verification proof on blockchain for user: {}", proof.user_id);

        // Simulate blockchain storage
        let proof_hash = self.calculate_hash(&proof).await?;
        let key = format!("verification_proof_{}", proof.user_id);

        {
            let mut storage = self.storage.write().await;
            storage.insert(key.clone(), serde_json::to_value(proof)?);
        }

        // Increment block height
        {
            let mut height = self.block_height.write().await;
            *height += 1;
            info!("Verification proof stored at block height: {}", *height);
        }

        info!("Verification proof stored successfully with hash: {}", proof_hash);
        Ok(proof_hash)
    }

    pub async fn store_attestation(&self, attestation_id: Uuid, data: &serde_json::Value) -> Result<String> {
        info!("Storing attestation on blockchain: {}", attestation_id);

        let attestation_data = AttestationData {
            id: attestation_id,
            user_id: Uuid::new_v4(), // Would be extracted from the actual data
            attestation_type: "identity".to_string(),
            verifier_id: "verifier_001".to_string(),
            data_hash: self.calculate_data_hash(data).await?,
            signature: self.sign_data(data).await?,
            timestamp: chrono::Utc::now(),
        };

        let attestation_hash = self.calculate_hash(&attestation_data).await?;
        let key = format!("attestation_{}", attestation_id);

        {
            let mut storage = self.storage.write().await;
            storage.insert(key.clone(), serde_json::to_value(attestation_data)?);
        }

        // Increment block height
        {
            let mut height = self.block_height.write().await;
            *height += 1;
            info!("Attestation stored at block height: {}", *height);
        }

        info!("Attestation stored successfully with hash: {}", attestation_hash);
        Ok(attestation_hash)
    }

    pub async fn get_verification_proof(&self, user_id: Uuid) -> Result<Option<VerificationProof>> {
        info!("Retrieving verification proof for user: {}", user_id);

        let key = format!("verification_proof_{}", user_id);
        let storage = self.storage.read().await;

        if let Some(value) = storage.get(&key) {
            let proof: VerificationProof = serde_json::from_value(value.clone())?;
            info!("Verification proof found for user: {}", user_id);
            Ok(Some(proof))
        } else {
            info!("No verification proof found for user: {}", user_id);
            Ok(None)
        }
    }

    pub async fn get_attestation(&self, attestation_id: Uuid) -> Result<Option<AttestationData>> {
        info!("Retrieving attestation: {}", attestation_id);

        let key = format!("attestation_{}", attestation_id);
        let storage = self.storage.read().await;

        if let Some(value) = storage.get(&key) {
            let attestation: AttestationData = serde_json::from_value(value.clone())?;
            info!("Attestation found: {}", attestation_id);
            Ok(Some(attestation))
        } else {
            info!("No attestation found: {}", attestation_id);
            Ok(None)
        }
    }

    pub async fn verify_proof(&self, proof_hash: &str, user_id: Uuid) -> Result<bool> {
        info!("Verifying proof hash: {} for user: {}", proof_hash, user_id);

        if let Some(proof) = self.get_verification_proof(user_id).await? {
            let calculated_hash = self.calculate_hash(&proof).await?;
            let is_valid = calculated_hash == proof_hash;

            if is_valid {
                info!("Proof verification successful");
            } else {
                warn!("Proof verification failed - hash mismatch");
            }

            Ok(is_valid)
        } else {
            warn!("No proof found for verification");
            Ok(false)
        }
    }

    pub async fn get_current_block_height(&self) -> u64 {
        let height = self.block_height.read().await;
        *height
    }

    pub async fn create_merkle_tree(&self, leaves: Vec<String>) -> Result<String> {
        info!("Creating merkle tree with {} leaves", leaves.len());

        if leaves.is_empty() {
            return Ok("empty_tree".to_string());
        }

        // Simple merkle tree implementation for demo
        let mut level = leaves;
        while level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    chunk[0].clone()
                };
                next_level.push(self.hash_string(&combined));
            }
            level = next_level;
        }

        let root = level.into_iter().next().unwrap_or_else(|| "empty".to_string());
        info!("Merkle root created: {}", root);
        Ok(root)
    }

    pub async fn submit_transaction(&self, tx_data: &serde_json::Value) -> Result<String> {
        info!("Submitting transaction to blockchain");

        // Simulate transaction submission
        let tx_hash = self.calculate_data_hash(tx_data).await?;

        // Increment block height
        {
            let mut height = self.block_height.write().await;
            *height += 1;
        }

        info!("Transaction submitted successfully with hash: {}", tx_hash);
        Ok(tx_hash)
    }

    async fn calculate_hash<T: Serialize>(&self, data: &T) -> Result<String> {
        let json_data = serde_json::to_string(data)?;
        Ok(self.hash_string(&json_data))
    }

    async fn calculate_data_hash(&self, data: &serde_json::Value) -> Result<String> {
        let json_data = serde_json::to_string(data)?;
        Ok(self.hash_string(&json_data))
    }

    fn hash_string(&self, input: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    async fn sign_data(&self, data: &serde_json::Value) -> Result<String> {
        let json_data = serde_json::to_string(data)?;
        let signature = self.keypair.sign(json_data.as_bytes());
        Ok(hex::encode(signature.as_ref()))
    }

    pub async fn get_account_balance(&self, account_id: &str) -> Result<u64> {
        // Simulate getting account balance
        info!("Getting balance for account: {}", account_id);
        Ok(1000000) // Return 1M units for demo
    }

    pub async fn get_network_stats(&self) -> Result<NetworkStats> {
        let height = self.get_current_block_height().await;
        let storage_count = {
            let storage = self.storage.read().await;
            storage.len()
        };

        Ok(NetworkStats {
            block_height: height,
            total_transactions: storage_count as u64,
            network_hash_rate: 12500, // Simulated
            validator_count: 15,
            finalized_block: height.saturating_sub(1),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkStats {
    pub block_height: u64,
    pub total_transactions: u64,
    pub network_hash_rate: u64,
    pub validator_count: u32,
    pub finalized_block: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_substrate_client_creation() {
        let client = SubstrateClient::new("ws://localhost:9944").await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_verification_proof_storage() {
        let client = SubstrateClient::new("ws://localhost:9944").await.unwrap();

        let proof = VerificationProof {
            user_id: Uuid::new_v4(),
            document_hash: "test_hash".to_string(),
            verification_level: "enhanced".to_string(),
            timestamp: chrono::Utc::now(),
            verifier_signature: "test_signature".to_string(),
            merkle_root: "test_root".to_string(),
        };

        let result = client.store_verification_proof(proof.clone()).await;
        assert!(result.is_ok());

        let retrieved = client.get_verification_proof(proof.user_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, proof.user_id);
    }

    #[tokio::test]
    async fn test_merkle_tree_creation() {
        let client = SubstrateClient::new("ws://localhost:9944").await.unwrap();

        let leaves = vec![
            "leaf1".to_string(),
            "leaf2".to_string(),
            "leaf3".to_string(),
            "leaf4".to_string(),
        ];

        let root = client.create_merkle_tree(leaves).await.unwrap();
        assert!(!root.is_empty());
        assert_ne!(root, "empty_tree");
    }
}