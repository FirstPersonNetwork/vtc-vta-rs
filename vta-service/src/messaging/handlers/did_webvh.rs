use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

use vta_sdk::protocols::did_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::send_response;
use crate::operations;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_create_did_webvh(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::did_management::create::CreateDidWebvhBody =
        serde_json::from_value(msg.body.clone())?;

    let config = state.config.read().await;
    let params = operations::did_webvh::CreateDidWebvhParams {
        context_id: body.context_id,
        server_id: body.server_id,
        path: body.path,
        label: body.label,
        portable: body.portable.unwrap_or(true),
        add_mediator_service: body.add_mediator_service.unwrap_or(false),
        additional_services: body.additional_services,
        pre_rotation_count: body.pre_rotation_count.unwrap_or(0),
    };

    let did_resolver = state.did_resolver.as_ref().ok_or_else(|| {
        Box::<dyn std::error::Error + Send + Sync>::from("DID resolver not available")
    })?;
    let result = operations::did_webvh::create_did_webvh(
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &*state.seed_store,
        &config,
        &auth,
        params,
        did_resolver,
        &state.secrets_resolver,
        "didcomm",
    )
    .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::CREATE_DID_WEBVH_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_get_did_webvh(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::did_management::get::GetDidWebvhBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::did_webvh::get_did_webvh(&state.webvh_ks, &auth, &body.did, "didcomm")
            .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::GET_DID_WEBVH_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_list_dids_webvh(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::did_management::list::ListDidsWebvhBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::did_webvh::list_dids_webvh(
        &state.webvh_ks,
        &auth,
        body.context_id.as_deref(),
        body.server_id.as_deref(),
        "didcomm",
    )
    .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::LIST_DIDS_WEBVH_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_delete_did_webvh(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::did_management::delete::DeleteDidWebvhBody =
        serde_json::from_value(msg.body.clone())?;

    let config = state.config.read().await;
    let did_resolver = state.did_resolver.as_ref().ok_or_else(|| {
        Box::<dyn std::error::Error + Send + Sync>::from("DID resolver not available")
    })?;
    let result = operations::did_webvh::delete_did_webvh(
        &state.webvh_ks,
        &state.keys_ks,
        &*state.seed_store,
        &config,
        &auth,
        &body.did,
        did_resolver,
        &state.secrets_resolver,
        "didcomm",
    )
    .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::DELETE_DID_WEBVH_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_add_webvh_server(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::did_management::servers::AddWebvhServerBody =
        serde_json::from_value(msg.body.clone())?;

    let did_resolver = state.did_resolver.as_ref().ok_or_else(|| {
        Box::<dyn std::error::Error + Send + Sync>::from("DID resolver not available")
    })?;
    let result = operations::did_webvh::add_webvh_server(
        &state.webvh_ks,
        &auth,
        &body.id,
        &body.did,
        body.label,
        did_resolver,
        "didcomm",
    )
    .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::ADD_WEBVH_SERVER_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_list_webvh_servers(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let result =
        operations::did_webvh::list_webvh_servers(&state.webvh_ks, &auth, "didcomm").await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::LIST_WEBVH_SERVERS_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_update_webvh_server(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::did_management::servers::UpdateWebvhServerBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::did_webvh::update_webvh_server(
        &state.webvh_ks,
        &auth,
        &body.id,
        body.label,
        "didcomm",
    )
    .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::UPDATE_WEBVH_SERVER_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_remove_webvh_server(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::did_management::servers::RemoveWebvhServerBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::did_webvh::remove_webvh_server(&state.webvh_ks, &auth, &body.id, "didcomm")
            .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        did_management::REMOVE_WEBVH_SERVER_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
