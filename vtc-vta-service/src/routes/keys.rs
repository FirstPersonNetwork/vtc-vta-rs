use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::keys::derivation::{Bip32Extension, load_or_generate_seed};
use crate::keys::{self, KeyRecord, KeyStatus, KeyType};
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: KeyType,
    pub derivation_path: String,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub derivation_path: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct InvalidateKeyResponse {
    pub key_id: String,
    pub status: KeyStatus,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

#[derive(Debug, Serialize)]
pub struct RenameKeyResponse {
    pub key_id: String,
    pub updated_at: chrono::DateTime<Utc>,
}

pub async fn create_key(
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), AppError> {
    let keys = state.store.keyspace("keys")?;

    let bip32 = load_or_generate_seed(&state.seed_store, req.mnemonic.as_deref()).await?;

    let secret = match req.key_type {
        KeyType::Ed25519 => bip32.derive_ed25519(&req.derivation_path)?,
        KeyType::X25519 => bip32.derive_x25519(&req.derivation_path)?,
    };

    let now = Utc::now();
    let key_id = Uuid::new_v4().to_string();
    let public_key = secret.get_public_keymultibase()?;

    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: req.derivation_path.clone(),
        key_type: req.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: req.label.clone(),
        created_at: now,
        updated_at: now,
    };

    keys.insert(keys::store_key(&key_id), &record).await?;

    let response = CreateKeyResponse {
        key_id,
        key_type: req.key_type,
        derivation_path: req.derivation_path,
        public_key,
        status: KeyStatus::Active,
        label: req.label,
        created_at: now,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn get_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<KeyRecord>, AppError> {
    let keys = state.store.keyspace("keys")?;

    let record: KeyRecord = keys
        .get(keys::store_key(&key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    Ok(Json(record))
}

pub async fn invalidate_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<InvalidateKeyResponse>, AppError> {
    let keys = state.store.keyspace("keys")?;
    let store_key = keys::store_key(&key_id);

    let mut record: KeyRecord = keys
        .get(store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if record.status == KeyStatus::Revoked {
        return Err(AppError::Conflict(format!(
            "key {key_id} is already revoked"
        )));
    }

    record.status = KeyStatus::Revoked;
    record.updated_at = Utc::now();

    keys.insert(store_key, &record).await?;

    Ok(Json(InvalidateKeyResponse {
        key_id,
        status: record.status,
        updated_at: record.updated_at,
    }))
}

pub async fn rename_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, AppError> {
    let keys = state.store.keyspace("keys")?;
    let old_store_key = keys::store_key(&key_id);

    let mut record: KeyRecord = keys
        .get(old_store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    let new_store_key = keys::store_key(&req.key_id);
    record.key_id = req.key_id.clone();
    record.updated_at = Utc::now();

    if !keys.swap(old_store_key, new_store_key, &record).await? {
        return Err(AppError::Conflict(format!(
            "key {} already exists",
            req.key_id
        )));
    }

    Ok(Json(RenameKeyResponse {
        key_id: req.key_id,
        updated_at: record.updated_at,
    }))
}
