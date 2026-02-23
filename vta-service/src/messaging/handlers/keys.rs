use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

use vta_sdk::protocols::key_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::send_response;
use crate::operations;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_create_key(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::create::CreateKeyBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::keys::create_key(
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &auth,
        operations::keys::CreateKeyParams {
            key_type: body.key_type,
            derivation_path: if body.derivation_path.is_empty() {
                None
            } else {
                Some(body.derivation_path)
            },
            key_id: None,
            mnemonic: body.mnemonic,
            label: body.label,
            context_id: None,
        },
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::key_management::get::GetKeyBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::keys::get_key(&state.keys_ks, &auth, &body.key_id, "didcomm").await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        key_management::GET_KEY_RESULT,
        Some(&msg.id),
        &result,
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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::key_management::list::ListKeysBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::keys::list_keys(
        &state.keys_ks,
        &auth,
        operations::keys::ListKeysParams {
            offset: body.offset,
            limit: body.limit,
            status: body.status,
            context_id: body.context_id,
        },
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::rename::RenameKeyBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::keys::rename_key(
        &state.keys_ks,
        &auth,
        &body.key_id,
        &body.new_key_id,
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::revoke::RevokeKeyBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::keys::revoke_key(&state.keys_ks, &auth, &body.key_id, "didcomm").await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::key_management::secret::GetKeySecretBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::keys::get_key_secret(
        &state.keys_ks,
        &state.seed_store,
        &auth,
        &body.key_id,
        "didcomm",
    )
    .await?;

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
