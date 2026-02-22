use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use serde::Serialize;
use tracing::warn;
use uuid::Uuid;

const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

/// Build a DIDComm response message, pack it, and send it via the mediator.
pub async fn send_response<T: Serialize>(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    recipient_did: &str,
    msg_type: &str,
    thid: Option<&str>,
    body: &T,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body_value = serde_json::to_value(body)?;

    let mut msg = Message::build(Uuid::new_v4().to_string(), msg_type.to_string(), body_value)
        .from(vta_did.to_string())
        .to(recipient_did.to_string());

    if let Some(thid) = thid {
        msg = msg.thid(thid.to_string());
    }

    let msg = msg.finalize();

    let (packed, _) = atm
        .pack_encrypted(&msg, recipient_did, Some(vta_did), Some(vta_did), None)
        .await?;

    atm.send_message(profile, &packed, &msg.id, false, false)
        .await?;

    Ok(())
}

/// Send a problem-report error response.
pub async fn send_error(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    recipient_did: &str,
    thid: Option<&str>,
    code: &str,
    comment: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = serde_json::json!({
        "code": code,
        "comment": comment,
    });

    let mut msg = Message::build(
        Uuid::new_v4().to_string(),
        PROBLEM_REPORT_TYPE.to_string(),
        body,
    )
    .from(vta_did.to_string())
    .to(recipient_did.to_string());

    if let Some(thid) = thid {
        msg = msg.thid(thid.to_string());
    }

    let msg = msg.finalize();

    let (packed, _) = atm
        .pack_encrypted(&msg, recipient_did, Some(vta_did), Some(vta_did), None)
        .await?;

    if let Err(e) = atm
        .send_message(profile, &packed, &msg.id, false, false)
        .await
    {
        warn!("failed to send problem-report: {e}");
    }

    Ok(())
}
