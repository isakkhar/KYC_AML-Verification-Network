use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub key: String,
    pub value: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub block_height: u64,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageQuery {
    pub key_prefix: Option<String>,
    pub block_height_range: Option<(u64, u64)>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub struct BlockchainStorage {
    entries: Arc<RwLock<HashMap<String, StorageEntry>>>,
    current_block: Arc<RwLock<u64>>,
}

impl BlockchainStorage {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            current_block: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn store(&self, key: String, value: serde_json::Value) -> Result<StorageEntry> {
        info!("Storing data with key: {}", key);

        let block_height = {
            let mut current = self.current_block.write().await;
            *current += 1;
            *current
        };

        let transaction_hash = self.generate_transaction_hash(&key, &value, block_height);
        let now = chrono::Utc::now();

        let entry = StorageEntry {
            key: key.clone(),
            value,
            created_at: now,
            updated_at: now,
            block_height,
            transaction_hash,
        };

        {
            let mut entries = self.entries.write().await;
            entries.insert(key.clone(), entry.clone());
        }

        info!("Data stored successfully at block height: {}", block_height);
        Ok(entry)
    }

    pub async fn get(&self, key: &str) -> Result<Option<StorageEntry>> {
        info!("Retrieving data with key: {}", key);

        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(key) {
            info!("Data found for key: {}", key);
            Ok(Some(entry.clone()))
        } else {
            info!("No data found for key: {}", key);
            Ok(None)
        }
    }

    pub async fn update(&self, key: String, value: serde_json::Value) -> Result<StorageEntry> {
        info!("Updating data with key: {}", key);

        let mut entries = self.entries.write().await;
        if let Some(existing_entry) = entries.get_mut(&key) {
            let block_height = {
                let mut current = self.current_block.write().await;
                *current += 1;
                *current
            };

            let transaction_hash = self.generate_transaction_hash(&key, &value, block_height);
            let now = chrono::Utc::now();

            existing_entry.value = value;
            existing_entry.updated_at = now;
            existing_entry.block_height = block_height;
            existing_entry.transaction_hash = transaction_hash.clone();

            info!("Data updated at block height: {}", block_height);
            Ok(existing_entry.clone())
        } else {
            error!("Attempted to update non-existent key: {}", key);
            anyhow::bail!("Key not found")
        }
    }

    pub async fn query(&self, query: StorageQuery) -> Result<Vec<StorageEntry>> {
        info!("Running query: {:?}", query);

        let entries = self.entries.read().await;
        let mut results: Vec<StorageEntry> = entries
            .values()
            .filter(|entry| {
                if let Some(prefix) = &query.key_prefix {
                    if !entry.key.starts_with(prefix) {
                        return false;
                    }
                }

                if let Some((start, end)) = query.block_height_range {
                    if entry.block_height < start || entry.block_height > end {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        results.sort_by_key(|e| e.block_height);

        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(results.len());

        let paginated: Vec<StorageEntry> = results.into_iter().skip(offset).take(limit).collect();
        Ok(paginated)
    }

    fn generate_transaction_hash(
        &self,
        key: &str,
        value: &serde_json::Value,
        block_height: u64,
    ) -> String {
        // For demonstration, just use a UUID. You could use a real hashing mechanism here.
        Uuid::new_v4().to_string()
    }
}
