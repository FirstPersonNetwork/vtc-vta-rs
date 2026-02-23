use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

use vta_sdk::protocols::acl_management;

use crate::acl::Role;
use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::send_response;
use crate::operations;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_create_acl(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::acl_management::create::CreateAclBody =
        serde_json::from_value(msg.body.clone())?;

    let role = Role::from_str(&body.role)?;

    let result = operations::acl::create_acl(
        &state.acl_ks,
        &auth,
        &body.did,
        role,
        body.label,
        body.allowed_contexts,
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::acl_management::get::GetAclBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::acl::get_acl(&state.acl_ks, &auth, &body.did, "didcomm").await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::acl_management::list::ListAclBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::acl::list_acl(
        &state.acl_ks,
        &auth,
        body.context.as_deref(),
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::acl_management::update::UpdateAclBody =
        serde_json::from_value(msg.body.clone())?;

    let role = match body.role {
        Some(r) => Some(Role::from_str(&r)?),
        None => None,
    };

    let result = operations::acl::update_acl(
        &state.acl_ks,
        &auth,
        &body.did,
        operations::acl::UpdateAclParams {
            role,
            label: body.label,
            allowed_contexts: body.allowed_contexts,
        },
        "didcomm",
    )
    .await?;

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
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::acl_management::delete::DeleteAclBody =
        serde_json::from_value(msg.body.clone())?;

    let result =
        operations::acl::delete_acl(&state.acl_ks, &auth, &body.did, "didcomm").await?;

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
