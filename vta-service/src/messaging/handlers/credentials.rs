use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;

use vta_sdk::protocols::credential_management;

use crate::acl::Role;
use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::send_response;
use crate::operations;

type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn handle_generate_credentials(
    state: &DidcommState,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::credential_management::generate::GenerateCredentialsBody =
        serde_json::from_value(msg.body.clone())?;

    let role = Role::from_str(&body.role)?;

    let result = operations::credentials::generate_credentials(
        &state.acl_ks,
        &state.config,
        &auth,
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
        credential_management::GENERATE_CREDENTIALS_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
