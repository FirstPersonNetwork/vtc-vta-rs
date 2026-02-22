use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tracing::info;

use vta_sdk::protocols::vta_management;

use crate::error::AppError;
use crate::messaging::DidcommState;
use crate::messaging::auth::DidcommAuth;
use crate::messaging::response::send_response;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_get_config(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    // Any authenticated DID in the ACL can read config

    let config = state.config.read().await;

    info!(caller = %auth.did, "config retrieved (DIDComm)");

    let result = vta_sdk::protocols::vta_management::get_config::GetConfigResultBody {
        vta_did: config.vta_did.clone(),
        vta_name: config.vta_name.clone(),
        public_url: config.public_url.clone(),
    };

    drop(config);

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
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_super_admin()?;

    let body: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody =
        serde_json::from_value(msg.body.clone())?;

    let (result, contents, path) = {
        let mut config = state.config.write().await;

        if let Some(vta_did_val) = body.vta_did {
            config.vta_did = Some(vta_did_val);
        }
        if let Some(vta_name) = body.vta_name {
            config.vta_name = Some(vta_name);
        }
        if let Some(public_url) = body.public_url {
            config.public_url = Some(public_url);
        }

        let result = vta_sdk::protocols::vta_management::get_config::GetConfigResultBody {
            vta_did: config.vta_did.clone(),
            vta_name: config.vta_name.clone(),
            public_url: config.public_url.clone(),
        };
        let contents = toml::to_string_pretty(&*config)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        let path = config.config_path.clone();

        (result, contents, path)
    };

    std::fs::write(&path, contents).map_err(AppError::Io)?;

    info!(caller = %auth.did, "config updated (DIDComm)");

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
