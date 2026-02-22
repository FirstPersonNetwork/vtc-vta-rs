use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tracing::info;

use vta_sdk::credentials::CredentialBundle;
use vta_sdk::protocols::credential_management;

use crate::acl::{AclEntry, Role, store_acl_entry, validate_acl_modification};
use crate::auth::credentials::generate_did_key;
use crate::auth::extractor::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::messaging::DidcommState;
use crate::messaging::auth::DidcommAuth;
use crate::messaging::response::send_response;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_generate_credentials(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = DidcommAuth::from_message(msg, &state.acl_ks).await?;
    auth.require_manage()?;

    let body: vta_sdk::protocols::credential_management::generate::GenerateCredentialsBody =
        serde_json::from_value(msg.body.clone())?;

    let role = Role::from_str(&body.role)?;

    let claims = AuthClaims {
        did: auth.did.clone(),
        role: auth.role.clone(),
        allowed_contexts: auth.allowed_contexts.clone(),
    };
    validate_acl_modification(&claims, &body.allowed_contexts)?;

    let config = state.config.read().await;
    let config_vta_did = config
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    let vta_url = config.public_url.clone();
    drop(config);

    let (did, private_key_multibase) = generate_did_key();

    let entry = AclEntry {
        did: did.clone(),
        role: role.clone(),
        label: body.label,
        allowed_contexts: body.allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.did.clone(),
    };
    store_acl_entry(&state.acl_ks, &entry).await?;

    let bundle = CredentialBundle {
        did: did.clone(),
        private_key_multibase,
        vta_did: config_vta_did,
        vta_url,
    };
    let credential = bundle.encode().map_err(|e| AppError::Internal(e.to_string()))?;

    info!(did = %did, role = %role, caller = %auth.did, "credentials generated (DIDComm)");

    let result = vta_sdk::protocols::credential_management::generate::GenerateCredentialsResultBody {
        did,
        credential,
        role: role.to_string(),
    };

    send_response(
        atm,
        profile,
        vta_did,
        &auth.did,
        credential_management::GENERATE_CREDENTIALS_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
