use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tracing::info;

use vta_sdk::protocols::seed_management;

use crate::error::AppError;
use crate::keys::seeds::{self as seeds, get_active_seed_id};
use crate::messaging::DidcommState;
use crate::messaging::auth::DidcommAuth;
use crate::messaging::response::send_response;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_list_seeds(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let active_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let records = seeds::list_seed_records(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let seeds_info: Vec<vta_sdk::protocols::seed_management::list::SeedInfo> = records
        .into_iter()
        .map(|r| vta_sdk::protocols::seed_management::list::SeedInfo {
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

    info!(count = seeds_info.len(), active_id, "seeds listed (DIDComm)");

    let result = vta_sdk::protocols::seed_management::list::ListSeedsResultBody {
        seeds: seeds_info,
        active_seed_id: active_id,
    };

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
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_admin()?;

    let body: vta_sdk::protocols::seed_management::rotate::RotateSeedBody =
        serde_json::from_value(msg.body.clone())?;

    let previous_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let new_id =
        seeds::rotate_seed(&state.keys_ks, &*state.seed_store, body.mnemonic.as_deref())
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;

    info!(previous_id, new_id, "seed rotated (DIDComm)");

    let result = vta_sdk::protocols::seed_management::rotate::RotateSeedResultBody {
        previous_seed_id: previous_id,
        new_seed_id: new_id,
    };

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
