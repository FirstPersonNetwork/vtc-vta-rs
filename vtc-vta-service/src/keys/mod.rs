pub mod derivation;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Ed25519,
    X25519,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: Uuid,
    pub derivation_path: String,
    pub key_type: KeyType,
    pub status: KeyStatus,
    pub public_key: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl KeyRecord {
    pub fn store_key(id: &Uuid) -> String {
        format!("key:{id}")
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "ed25519"),
            KeyType::X25519 => write!(f, "x25519"),
        }
    }
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "active"),
            KeyStatus::Revoked => write!(f, "revoked"),
        }
    }
}
