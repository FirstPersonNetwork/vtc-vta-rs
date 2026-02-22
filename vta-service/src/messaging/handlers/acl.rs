use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tracing::info;

use vta_sdk::protocols::acl_management;

use crate::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_acl_modification,
};
use crate::auth::extractor::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::messaging::DidcommState;
use crate::messaging::auth::DidcommAuth;
use crate::messaging::response::send_response;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Convert a DidcommAuth to the AuthClaims used by ACL validation helpers.
fn to_auth_claims(auth: &DidcommAuth) -> AuthClaims {
    AuthClaims {
        did: auth.did.clone(),
        role: auth.role.clone(),
        allowed_contexts: auth.allowed_contexts.clone(),
    }
}

fn to_result_body(
    e: &AclEntry,
) -> vta_sdk::protocols::acl_management::create::CreateAclResultBody {
    vta_sdk::protocols::acl_management::create::CreateAclResultBody {
        did: e.did.clone(),
        role: e.role.to_string(),
        label: e.label.clone(),
        allowed_contexts: e.allowed_contexts.clone(),
        created_at: e.created_at,
        created_by: e.created_by.clone(),
    }
}

pub async fn handle_create_acl(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_manage()?;

    let body: vta_sdk::protocols::acl_management::create::CreateAclBody =
        serde_json::from_value(msg.body.clone())?;

    let claims = to_auth_claims(&auth);
    validate_acl_modification(&claims, &body.allowed_contexts)?;

    if get_acl_entry(&state.acl_ks, &body.did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {}",
            body.did
        ))
        .into());
    }

    let role = Role::from_str(&body.role)?;

    let entry = AclEntry {
        did: body.did,
        role,
        label: body.label,
        allowed_contexts: body.allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.did.clone(),
    };

    store_acl_entry(&state.acl_ks, &entry).await?;

    info!(caller = %auth.did, did = %entry.did, role = %entry.role, "ACL entry created (DIDComm)");

    let result = to_result_body(&entry);

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        acl_management::CREATE_ACL_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_get_acl(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_manage()?;

    let body: vta_sdk::protocols::acl_management::get::GetAclBody =
        serde_json::from_value(msg.body.clone())?;

    let entry = get_acl_entry(&state.acl_ks, &body.did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {}", body.did)))?;

    let claims = to_auth_claims(&auth);
    if !is_acl_entry_visible(&claims, &entry) {
        return Err(
            AppError::NotFound(format!("ACL entry not found for DID: {}", body.did)).into(),
        );
    }

    info!(did = %body.did, "ACL entry retrieved (DIDComm)");

    let result = to_result_body(&entry);

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        acl_management::GET_ACL_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_list_acl(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_manage()?;

    let body: vta_sdk::protocols::acl_management::list::ListAclBody =
        serde_json::from_value(msg.body.clone())?;

    let claims = to_auth_claims(&auth);
    let all_entries = list_acl_entries(&state.acl_ks).await?;
    let entries: Vec<_> = all_entries
        .iter()
        .filter(|e| is_acl_entry_visible(&claims, e))
        .filter(|e| match &body.context {
            Some(ctx) => e.allowed_contexts.contains(ctx),
            None => true,
        })
        .map(to_result_body)
        .collect();

    info!(caller = %auth.did, count = entries.len(), "ACL listed (DIDComm)");

    let result = vta_sdk::protocols::acl_management::list::ListAclResultBody { entries };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        acl_management::LIST_ACL_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_update_acl(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_manage()?;

    let body: vta_sdk::protocols::acl_management::update::UpdateAclBody =
        serde_json::from_value(msg.body.clone())?;

    let mut entry = get_acl_entry(&state.acl_ks, &body.did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {}", body.did)))?;

    let claims = to_auth_claims(&auth);
    if !is_acl_entry_visible(&claims, &entry) {
        return Err(
            AppError::NotFound(format!("ACL entry not found for DID: {}", body.did)).into(),
        );
    }

    if let Some(role_str) = body.role {
        entry.role = Role::from_str(&role_str)?;
    }
    if let Some(label) = body.label {
        entry.label = Some(label);
    }
    if let Some(allowed_contexts) = body.allowed_contexts {
        validate_acl_modification(&claims, &allowed_contexts)?;
        entry.allowed_contexts = allowed_contexts;
    }

    store_acl_entry(&state.acl_ks, &entry).await?;

    info!(did = %body.did, "ACL entry updated (DIDComm)");

    let result = to_result_body(&entry);

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        acl_management::UPDATE_ACL_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_delete_acl(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_manage()?;

    let body: vta_sdk::protocols::acl_management::delete::DeleteAclBody =
        serde_json::from_value(msg.body.clone())?;

    if auth.did == body.did {
        return Err(AppError::Conflict("cannot delete your own ACL entry".into()).into());
    }

    let entry = get_acl_entry(&state.acl_ks, &body.did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {}", body.did)))?;

    let claims = to_auth_claims(&auth);
    if !is_acl_entry_visible(&claims, &entry) {
        return Err(
            AppError::NotFound(format!("ACL entry not found for DID: {}", body.did)).into(),
        );
    }

    delete_acl_entry(&state.acl_ks, &body.did).await?;

    info!(caller = %auth.did, did = %body.did, "ACL entry deleted (DIDComm)");

    let result = vta_sdk::protocols::acl_management::delete::DeleteAclResultBody {
        did: body.did,
        deleted: true,
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        acl_management::DELETE_ACL_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
