use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use chrono::Utc;
use tracing::info;

use vta_sdk::protocols::key_management;

use crate::contexts::get_context;
use crate::error::AppError;
use crate::keys::derivation::Bip32Extension;
use crate::keys::paths::allocate_path;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyRecord, KeyStatus, KeyType};
use crate::messaging::DidcommState;
use crate::messaging::auth::DidcommAuth;
use crate::messaging::response::send_response;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_create_key(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::create::CreateKeyBody =
        serde_json::from_value(msg.body.clone())?;

    // Resolve context
    let context_id = if auth.is_super_admin() {
        None
    } else if let Some(ctx) = auth.default_context() {
        Some(ctx.to_string())
    } else {
        return Err(AppError::Forbidden(
            "context_id required: admin has access to multiple contexts".into(),
        )
        .into());
    };

    let derivation_path = match body.derivation_path.as_str() {
        "" => {
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
        path => path.to_string(),
    };

    if body.mnemonic.is_some() {
        return Err(AppError::Validation(
            "mnemonic is not accepted via the API — use seed rotation instead".into(),
        )
        .into());
    }

    let active_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(&state.keys_ks, &*state.seed_store, Some(active_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| AppError::KeyDerivation(format!("failed to create BIP-32 root key: {e}")))?;

    let secret = match body.key_type {
        KeyType::Ed25519 => bip32.derive_ed25519(&derivation_path)?,
        KeyType::X25519 => bip32.derive_x25519(&derivation_path)?,
    };

    let now = Utc::now();
    let key_id = derivation_path.clone();
    let public_key = secret.get_public_keymultibase()?;

    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: derivation_path.clone(),
        key_type: body.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: body.label.clone(),
        context_id: context_id.clone(),
        seed_id: Some(active_id),
        created_at: now,
        updated_at: now,
    };

    state
        .keys_ks
        .insert(keys::store_key(&key_id), &record)
        .await?;

    info!(key_id = %key_id, key_type = ?body.key_type, path = %derivation_path, "key created (DIDComm)");

    let result = vta_sdk::protocols::key_management::create::CreateKeyResultBody {
        key_id,
        key_type: body.key_type,
        derivation_path,
        public_key,
        status: KeyStatus::Active,
        label: body.label,
        created_at: now,
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        key_management::CREATE_KEY_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_get_key(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::key_management::get::GetKeyBody =
        serde_json::from_value(msg.body.clone())?;

    let record: KeyRecord = state
        .keys_ks
        .get(keys::store_key(&body.key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {} not found", body.key_id)))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(
            AppError::Forbidden("only super admin can access keys without a context".into())
                .into(),
        );
    }

    info!(key_id = %body.key_id, "key retrieved (DIDComm)");

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        key_management::GET_KEY_RESULT,
        Some(&msg.id),
        &record,
    )
    .await
}

pub async fn handle_list_keys(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::key_management::list::ListKeysBody =
        serde_json::from_value(msg.body.clone())?;

    let raw = state.keys_ks.prefix_iter_raw("key:").await?;

    let mut records: Vec<KeyRecord> = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if let Some(ref status) = body.status
            && record.status != *status
        {
            continue;
        }
        if let Some(ref ctx) = body.context_id
            && record.context_id.as_deref() != Some(ctx.as_str())
        {
            continue;
        }
        if !auth.is_super_admin() {
            match record.context_id {
                Some(ref ctx) if auth.has_context_access(ctx) => {}
                _ => continue,
            }
        }
        records.push(record);
    }

    let total = records.len() as u64;
    let offset = body.offset.unwrap_or(0);
    let limit = body.limit.unwrap_or(50);

    let page: Vec<KeyRecord> = records
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    info!(caller = %auth.did, count = page.len(), total, "keys listed (DIDComm)");

    let result = vta_sdk::protocols::key_management::list::ListKeysResultBody {
        keys: page,
        total,
        offset,
        limit,
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        key_management::LIST_KEYS_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_rename_key(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::rename::RenameKeyBody =
        serde_json::from_value(msg.body.clone())?;

    let old_store_key = keys::store_key(&body.key_id);
    let mut record: KeyRecord = state
        .keys_ks
        .get(old_store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {} not found", body.key_id)))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(
            AppError::Forbidden("only super admin can rename keys without a context".into())
                .into(),
        );
    }

    let new_store_key = keys::store_key(&body.new_key_id);
    record.key_id = body.new_key_id.clone();
    record.updated_at = Utc::now();

    if !state
        .keys_ks
        .swap(old_store_key, new_store_key, &record)
        .await?
    {
        return Err(
            AppError::Conflict(format!("key {} already exists", body.new_key_id)).into(),
        );
    }

    info!(old_id = %body.key_id, new_id = %body.new_key_id, "key renamed (DIDComm)");

    let result = vta_sdk::protocols::key_management::rename::RenameKeyResultBody {
        key_id: body.new_key_id,
        updated_at: record.updated_at,
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        key_management::RENAME_KEY_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_revoke_key(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::revoke::RevokeKeyBody =
        serde_json::from_value(msg.body.clone())?;

    let store_key = keys::store_key(&body.key_id);
    let mut record: KeyRecord = state
        .keys_ks
        .get(store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {} not found", body.key_id)))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(
            AppError::Forbidden("only super admin can revoke keys without a context".into())
                .into(),
        );
    }

    if record.status == KeyStatus::Revoked {
        return Err(
            AppError::Conflict(format!("key {} is already revoked", body.key_id)).into(),
        );
    }

    record.status = KeyStatus::Revoked;
    record.updated_at = Utc::now();

    state.keys_ks.insert(store_key, &record).await?;

    info!(key_id = %body.key_id, "key revoked (DIDComm)");

    let result = vta_sdk::protocols::key_management::revoke::RevokeKeyResultBody {
        key_id: body.key_id,
        status: record.status,
        updated_at: record.updated_at,
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        key_management::REVOKE_KEY_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_get_key_secret(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::secret::GetKeySecretBody =
        serde_json::from_value(msg.body.clone())?;

    let record: KeyRecord = state
        .keys_ks
        .get(keys::store_key(&body.key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {} not found", body.key_id)))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(
            AppError::Forbidden("only super admin can access keys without a context".into())
                .into(),
        );
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

    info!(key_id = %body.key_id, "key secret retrieved (DIDComm)");

    let result = vta_sdk::protocols::key_management::secret::GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase: secret.get_public_keymultibase()?,
        private_key_multibase: secret.get_private_keymultibase()?,
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        key_management::GET_KEY_SECRET_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
