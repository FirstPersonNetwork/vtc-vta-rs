use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

use vta_sdk::protocols::seed_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::send_response;
use crate::operations;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_list_seeds(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let result = operations::seeds::list_seeds(&state.keys_ks, "didcomm").await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        seed_management::LIST_SEEDS_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

pub async fn handle_rotate_seed(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::seed_management::rotate::RotateSeedBody =
        serde_json::from_value(msg.body.clone())?;

    let result = operations::seeds::rotate_seed(
        &state.keys_ks,
        &state.seed_store,
        body.mnemonic.as_deref(),
        "didcomm",
    )
    .await?;

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        seed_management::ROTATE_SEED_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
