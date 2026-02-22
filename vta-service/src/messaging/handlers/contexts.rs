use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use chrono::Utc;
use tracing::info;

use vta_sdk::protocols::context_management;

use crate::contexts::{
    ContextRecord, allocate_context_index, delete_context, get_context, list_contexts,
    store_context,
};
use crate::error::AppError;
use crate::messaging::DidcommState;
use crate::messaging::auth::DidcommAuth;
use crate::messaging::response::send_response;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn to_result_body(
    r: &ContextRecord,
) -> vta_sdk::protocols::context_management::create::CreateContextResultBody {
    vta_sdk::protocols::context_management::create::CreateContextResultBody {
        id: r.id.clone(),
        name: r.name.clone(),
        did: r.did.clone(),
        description: r.description.clone(),
        base_path: r.base_path.clone(),
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

pub async fn handle_create_context(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_super_admin()?;

    let body: vta_sdk::protocols::context_management::create::CreateContextBody =
        serde_json::from_value(msg.body.clone())?;

    if get_context(&state.contexts_ks, &body.id).await?.is_some() {
        return Err(
            AppError::Conflict(format!("context already exists: {}", body.id)).into(),
        );
    }

    let (index, base_path) = allocate_context_index(&state.contexts_ks).await?;

    let now = Utc::now();
    let record = ContextRecord {
        id: body.id.clone(),
        name: body.name,
        did: None,
        description: body.description,
        base_path,
        index,
        created_at: now,
        updated_at: now,
    };

    store_context(&state.contexts_ks, &record).await?;

    info!(id = %record.id, index, "context created (DIDComm)");

    let result = to_result_body(&record);

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        context_management::CREATE_CONTEXT_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_get_context(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::context_management::get::GetContextBody =
        serde_json::from_value(msg.body.clone())?;

    auth.require_context(&body.id)?;

    let record = get_context(&state.contexts_ks, &body.id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", body.id)))?;

    info!(id = %body.id, "context retrieved (DIDComm)");

    let result = to_result_body(&record);

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        context_management::GET_CONTEXT_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_list_contexts(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;

    let records = list_contexts(&state.contexts_ks).await?;
    let contexts: Vec<_> = records
        .iter()
        .filter(|r| auth.has_context_access(&r.id))
        .map(to_result_body)
        .collect();

    info!(caller = %auth.did, count = contexts.len(), "contexts listed (DIDComm)");

    let result = vta_sdk::protocols::context_management::list::ListContextsResultBody { contexts };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        context_management::LIST_CONTEXTS_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_update_context(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_super_admin()?;

    let body: vta_sdk::protocols::context_management::update::UpdateContextBody =
        serde_json::from_value(msg.body.clone())?;

    let mut record = get_context(&state.contexts_ks, &body.id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", body.id)))?;

    if let Some(name) = body.name {
        record.name = name;
    }
    if let Some(did) = body.did {
        record.did = Some(did);
    }
    if let Some(description) = body.description {
        record.description = Some(description);
    }
    record.updated_at = Utc::now();

    store_context(&state.contexts_ks, &record).await?;

    info!(id = %body.id, "context updated (DIDComm)");

    let result = to_result_body(&record);

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        context_management::UPDATE_CONTEXT_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_delete_context(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_super_admin()?;

    let body: vta_sdk::protocols::context_management::delete::DeleteContextBody =
        serde_json::from_value(msg.body.clone())?;

    get_context(&state.contexts_ks, &body.id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", body.id)))?;

    delete_context(&state.contexts_ks, &body.id).await?;

    info!(id = %body.id, "context deleted (DIDComm)");

    let result = vta_sdk::protocols::context_management::delete::DeleteContextResultBody {
        id: body.id,
        deleted: true,
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        context_management::DELETE_CONTEXT_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
