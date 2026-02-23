use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

use vta_sdk::protocols::vta_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::send_response;
use crate::operations;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_get_config(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let result =
        operations::config::get_config(&state.config, &auth, "didcomm").await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        vta_management::GET_CONFIG_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_update_config(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::config::update_config(
        &state.config,
        &auth,
        operations::config::UpdateConfigParams {
            vta_did: body.vta_did,
            vta_name: body.vta_name,
            public_url: body.public_url,
        },
        "didcomm",
    )
    .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        vta_management::UPDATE_CONFIG_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
