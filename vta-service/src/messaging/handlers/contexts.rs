use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

use vta_sdk::protocols::context_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::send_response;
use crate::operations;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_create_context(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::context_management::create::CreateContextBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::contexts::create_context(
        &state.contexts_ks,
        &auth,
        &body.id,
        body.name,
        body.description,
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::context_management::get::GetContextBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::contexts::get_context_op(&state.contexts_ks, &auth, &body.id, "didcomm")
            .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let result =
        operations::contexts::list_contexts(&state.contexts_ks, &auth, "didcomm").await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::context_management::update::UpdateContextBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::contexts::update_context(
        &state.contexts_ks,
        &auth,
        &body.id,
        operations::contexts::UpdateContextParams {
            name: body.name,
            did: body.did,
            description: body.description,
        },
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::context_management::delete::DeleteContextBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::contexts::delete_context(&state.contexts_ks, &auth, &body.id, "didcomm")
            .await?;

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
