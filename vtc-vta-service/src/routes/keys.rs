use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::keys::derivation::{
    derive_ed25519, derive_x25519, load_or_generate_seed, multibase_encode,
};
use crate::keys::{KeyRecord, KeyStatus, KeyType};
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
    pub id: Uuid,
    pub key_type: KeyType,
    pub derivation_path: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct InvalidateKeyResponse {
    pub id: Uuid,
    pub status: KeyStatus,
    pub updated_at: chrono::DateTime<Utc>,
}

pub async fn create_key(
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), AppError> {
    let secrets = state.store.keyspace("secrets")?;
    let keys = state.store.keyspace("keys")?;

    let seed = load_or_generate_seed(&secrets, req.mnemonic.as_deref()).await?;

    let (_, public_bytes) = match req.key_type {
        KeyType::Ed25519 => derive_ed25519(&seed, &req.derivation_path)?,
        KeyType::X25519 => derive_x25519(&seed, &req.derivation_path)?,
    };

    let now = Utc::now();
    let id = Uuid::new_v4();
    let public_key = multibase_encode(&public_bytes);

    let record = KeyRecord {
        id,
        derivation_path: req.derivation_path.clone(),
        key_type: req.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: req.label.clone(),
        created_at: now,
        updated_at: now,
    };

    keys.insert(KeyRecord::store_key(&id), &record).await?;

    let response = CreateKeyResponse {
        id,
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
    Path(id): Path<Uuid>,
) -> Result<Json<KeyRecord>, AppError> {
    let keys = state.store.keyspace("keys")?;

    let record: KeyRecord = keys
        .get(KeyRecord::store_key(&id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {id} not found")))?;

    Ok(Json(record))
}

pub async fn invalidate_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<InvalidateKeyResponse>, AppError> {
    let keys = state.store.keyspace("keys")?;
    let store_key = KeyRecord::store_key(&id);

    let mut record: KeyRecord = keys
        .get(store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {id} not found")))?;

    if record.status == KeyStatus::Revoked {
        return Err(AppError::Conflict(format!("key {id} is already revoked")));
    }

    record.status = KeyStatus::Revoked;
    record.updated_at = Utc::now();

    keys.insert(store_key, &record).await?;

    Ok(Json(InvalidateKeyResponse {
        id,
        status: record.status,
        updated_at: record.updated_at,
    }))
}
