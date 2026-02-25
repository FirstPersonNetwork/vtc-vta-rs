use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tokio::sync::oneshot;
use tracing::info;

use crate::error::AppError;

/// Bridge between REST/DIDComm handlers and the main ATM connection.
///
/// Provides request-response DIDComm messaging by registering oneshot channels
/// keyed by message ID. The main DIDComm loop checks incoming messages against
/// pending requests and routes matches directly to the waiting handler.
pub struct DIDCommBridge {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pending: std::sync::Mutex<HashMap<String, oneshot::Sender<Message>>>,
}

impl DIDCommBridge {
    pub fn new(atm: Arc<ATM>, profile: Arc<ATMProfile>) -> Self {
        Self {
            atm,
            profile,
            pending: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Register a pending request. Returns a receiver that will get the response.
    pub fn register_pending(&self, msg_id: &str) -> oneshot::Receiver<Message> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(msg_id.to_string(), tx);
        rx
    }

    /// Cancel a pending request (e.g. on timeout or error).
    pub fn cancel_pending(&self, msg_id: &str) {
        self.pending.lock().unwrap().remove(msg_id);
    }

    /// Try to complete a pending request. Returns true if the message was routed.
    pub fn try_complete(&self, msg: &Message) -> bool {
        if let Some(thid) = &msg.thid
            && let Some(tx) = self.pending.lock().unwrap().remove(thid)
        {
            let _ = tx.send(msg.clone());
            return true;
        }
        false
    }

    /// Send a DIDComm message and wait for a response matching the thread ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_and_wait(
        &self,
        vta_did: &str,
        server_did: &str,
        msg_type: &str,
        body: serde_json::Value,
        expected_type: &str,
        problem_report_type: &str,
        timeout_secs: u64,
    ) -> Result<Message, AppError> {
        // Build message
        let msg_id = uuid::Uuid::new_v4().to_string();
        let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(vta_did.to_string())
            .to(server_did.to_string())
            .finalize();

        // Register pending before sending
        let rx = self.register_pending(&msg_id);

        // Pack and send
        let (packed, _) = self
            .atm
            .pack_encrypted(&msg, server_did, Some(vta_did), Some(vta_did), None)
            .await
            .map_err(|e| {
                self.cancel_pending(&msg_id);
                AppError::Internal(format!("failed to pack message: {e}"))
            })?;

        self.atm
            .send_message(&self.profile, &packed, &msg_id, false, false)
            .await
            .map_err(|e| {
                self.cancel_pending(&msg_id);
                AppError::Internal(format!("failed to send message: {e}"))
            })?;

        info!(msg_type, msg_id, server_did, "sending via didcomm bridge");

        // Wait for response with timeout
        let response = tokio::time::timeout(Duration::from_secs(timeout_secs), rx)
            .await
            .map_err(|_| {
                self.cancel_pending(&msg_id);
                AppError::Internal("timeout waiting for DIDComm response".into())
            })?
            .map_err(|_| {
                AppError::Internal("pending request channel dropped".into())
            })?;

        // Check for problem report
        if response.type_ == problem_report_type {
            let code = response
                .body
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let comment = response
                .body
                .get("comment")
                .and_then(|v| v.as_str())
                .unwrap_or("no details provided");
            return Err(AppError::BadGateway(format!(
                "remote server error [{code}]: {comment}"
            )));
        }

        // Verify expected type
        if response.type_ != expected_type {
            return Err(AppError::BadGateway(format!(
                "unexpected response from remote server: expected {expected_type}, got {}",
                response.type_
            )));
        }

        info!(response_type = %response.type_, "received via didcomm bridge");
        Ok(response)
    }
}
