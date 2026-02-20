use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use tracing::{debug, info};

use crate::auth::{AdminAuth, AuthClaims};
use crate::contexts::get_context;
use crate::error::AppError;
use crate::keys::derivation::Bip32Extension;
use crate::keys::paths::allocate_path;
use crate::keys::seeds::{self as seeds, get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyRecord, KeyStatus, KeyType};
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: KeyType,
    pub derivation_path: Option<String>,
    pub key_id: Option<String>,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
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
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), AppError> {
    // Resolve context: explicit > super-admin (None) > single-context default
    let context_id = if let Some(ref ctx) = req.context_id {
        auth.0.require_context(ctx)?;
        Some(ctx.clone())
    } else if auth.0.is_super_admin() {
        None
    } else if let Some(ctx) = auth.0.default_context() {
        Some(ctx.to_string())
    } else {
        return Err(AppError::Forbidden(
            "context_id required: admin has access to multiple contexts".into(),
        ));
    };

    let keys = state.keys_ks.clone();

    // Resolve derivation path: use explicit value, or auto-derive from context
    let derivation_path = match req.derivation_path {
        Some(path) => path,
        None => {
            let ctx_id = context_id.as_ref().ok_or_else(|| {
                AppError::Validation(
                    "derivation_path is required when context_id is not provided".into(),
                )
            })?;
            let ctx = get_context(&state.contexts_ks, ctx_id)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("context not found: {ctx_id}")))?;
            allocate_path(&state.keys_ks, &ctx.base_path).await?
        }
    };

    if req.mnemonic.is_some() {
        return Err(AppError::Validation(
            "mnemonic is not accepted via the API — use seed rotation instead".into(),
        ));
    }

    let active_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(&state.keys_ks, &*state.seed_store, Some(active_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| AppError::KeyDerivation(format!("failed to create BIP-32 root key: {e}")))?;

    let secret = match req.key_type {
        KeyType::Ed25519 => bip32.derive_ed25519(&derivation_path)?,
        KeyType::X25519 => bip32.derive_x25519(&derivation_path)?,
    };

    let now = Utc::now();
    let key_id = req
        .key_id
        .clone()
        .unwrap_or_else(|| derivation_path.clone());
    let public_key = secret.get_public_keymultibase()?;

    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: derivation_path.clone(),
        key_type: req.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: req.label.clone(),
        context_id: context_id.clone(),
        seed_id: Some(active_id),
        created_at: now,
        updated_at: now,
    };

    keys.insert(keys::store_key(&key_id), &record).await?;

    info!(key_id = %key_id, key_type = ?req.key_type, path = %derivation_path, "key created");

    let response = CreateKeyResponse {
        key_id,
        key_type: req.key_type,
        derivation_path,
        public_key,
        status: KeyStatus::Active,
        label: req.label,
        created_at: now,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

#[derive(Debug, Serialize)]
pub struct GetKeySecretResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key_multibase: String,
    pub private_key_multibase: String,
}

pub async fn get_key_secret(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<GetKeySecretResponse>, AppError> {
    let keys = state.keys_ks.clone();

    let record: KeyRecord = keys
        .get(keys::store_key(&key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.0.require_context(ctx)?;
    } else if !auth.0.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can access keys without a context".into(),
        ));
    }

    let seed = load_seed_bytes(&state.keys_ks, &*state.seed_store, record.seed_id)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| AppError::KeyDerivation(format!("failed to create BIP-32 root key: {e}")))?;

    let secret = match record.key_type {
        KeyType::Ed25519 => bip32.derive_ed25519(&record.derivation_path)?,
        KeyType::X25519 => bip32.derive_x25519(&record.derivation_path)?,
    };

    info!(key_id = %key_id, "key secret retrieved");

    Ok(Json(GetKeySecretResponse {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase: secret.get_public_keymultibase()?,
        private_key_multibase: secret.get_private_keymultibase()?,
    }))
}

pub async fn get_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<KeyRecord>, AppError> {
    let keys = state.keys_ks.clone();

    let record: KeyRecord = keys
        .get(keys::store_key(&key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can access keys without a context".into(),
        ));
    }

    info!(key_id = %key_id, "key retrieved");
    Ok(Json(record))
}

pub async fn invalidate_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<InvalidateKeyResponse>, AppError> {
    let keys = state.keys_ks.clone();
    let store_key = keys::store_key(&key_id);

    let mut record: KeyRecord = keys
        .get(store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.0.require_context(ctx)?;
    } else if !auth.0.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can revoke keys without a context".into(),
        ));
    }

    if record.status == KeyStatus::Revoked {
        return Err(AppError::Conflict(format!(
            "key {key_id} is already revoked"
        )));
    }

    record.status = KeyStatus::Revoked;
    record.updated_at = Utc::now();

    keys.insert(store_key, &record).await?;

    info!(key_id = %key_id, "key revoked");
    Ok(Json(InvalidateKeyResponse {
        key_id,
        status: record.status,
        updated_at: record.updated_at,
    }))
}

pub async fn rename_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, AppError> {
    let keys = state.keys_ks.clone();
    let old_store_key = keys::store_key(&key_id);

    let mut record: KeyRecord = keys
        .get(old_store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.0.require_context(ctx)?;
    } else if !auth.0.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can rename keys without a context".into(),
        ));
    }

    let new_store_key = keys::store_key(&req.key_id);
    record.key_id = req.key_id.clone();
    record.updated_at = Utc::now();

    if !keys.swap(old_store_key, new_store_key, &record).await? {
        return Err(AppError::Conflict(format!(
            "key {} already exists",
            req.key_id
        )));
    }

    info!(old_id = %key_id, new_id = %req.key_id, "key renamed");
    Ok(Json(RenameKeyResponse {
        key_id: req.key_id,
        updated_at: record.updated_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ListKeysQuery {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<KeyStatus>,
    pub context_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyRecord>,
    pub total: u64,
    pub offset: u64,
    pub limit: u64,
}

pub async fn list_keys(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<ListKeysResponse>, AppError> {
    let keys = state.keys_ks.clone();
    let approx_len = keys.approximate_len().await?;
    let raw = keys.prefix_iter_raw("key:").await?;

    debug!(
        approx_keyspace_len = approx_len,
        prefix_scan_results = raw.len(),
        "keys list: scanning keyspace"
    );

    let mut records: Vec<KeyRecord> = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if let Some(ref status) = query.status
            && record.status != *status
        {
            continue;
        }
        if let Some(ref ctx) = query.context_id
            && record.context_id.as_deref() != Some(ctx.as_str())
        {
            continue;
        }
        // Context admins can only see keys within their assigned contexts
        if !auth.is_super_admin() {
            match record.context_id {
                Some(ref ctx) if auth.has_context_access(ctx) => {}
                _ => continue,
            }
        }
        records.push(record);
    }

    let total = records.len() as u64;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50);

    let page: Vec<KeyRecord> = records
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    let count = page.len();
    info!(caller = %auth.did, count, total, "keys listed");

    Ok(Json(ListKeysResponse {
        keys: page,
        total,
        offset,
        limit,
    }))
}

// ── Seed endpoints ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SeedInfoResponse {
    pub id: u32,
    pub status: String,
    pub created_at: chrono::DateTime<Utc>,
    pub retired_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ListSeedsResponse {
    pub seeds: Vec<SeedInfoResponse>,
    pub active_seed_id: u32,
}

pub async fn list_seeds(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ListSeedsResponse>, AppError> {
    let active_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let records = seeds::list_seed_records(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let seeds_info: Vec<SeedInfoResponse> = records
        .into_iter()
        .map(|r| SeedInfoResponse {
            id: r.id,
            status: if r.retired_at.is_some() {
                "retired".into()
            } else {
                "active".into()
            },
            created_at: r.created_at,
            retired_at: r.retired_at,
        })
        .collect();

    info!(count = seeds_info.len(), active_id, "seeds listed");

    Ok(Json(ListSeedsResponse {
        seeds: seeds_info,
        active_seed_id: active_id,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RotateSeedRequest {
    pub mnemonic: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RotateSeedResponse {
    pub previous_seed_id: u32,
    pub new_seed_id: u32,
}

pub async fn rotate_seed(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RotateSeedRequest>,
) -> Result<Json<RotateSeedResponse>, AppError> {
    let previous_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let new_id = seeds::rotate_seed(&state.keys_ks, &*state.seed_store, req.mnemonic.as_deref())
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    info!(previous_id, new_id, "seed rotated via API");

    Ok(Json(RotateSeedResponse {
        previous_seed_id: previous_id,
        new_seed_id: new_id,
    }))
}
