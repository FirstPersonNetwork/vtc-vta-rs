use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use tracing::debug;

use crate::error::AppError;
use crate::webvh_client::RequestUriResponse;

// WebVH DIDComm protocol message types
const MSG_DID_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/request";
const MSG_DID_OFFER: &str = "https://affinidi.com/webvh/1.0/did/offer";
const MSG_DID_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/publish";
const MSG_DID_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/confirm";
const MSG_DELETE: &str = "https://affinidi.com/webvh/1.0/did/delete";
const MSG_DELETE_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/delete-confirm";
const MSG_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/did/problem-report";

/// DIDComm-based client for communicating with a WebVH server.
///
/// Uses a short-lived ATM for each request-response exchange, following the
/// same pattern as `send_trust_ping` in `vta-sdk`.
pub struct WebvhDIDCommClient<'a> {
    secrets_resolver: &'a Arc<ThreadedSecretsResolver>,
    vta_did: &'a str,
    server_did: &'a str,
    mediator_did: &'a str,
}

impl<'a> WebvhDIDCommClient<'a> {
    pub fn new(
        secrets_resolver: &'a Arc<ThreadedSecretsResolver>,
        vta_did: &'a str,
        server_did: &'a str,
        mediator_did: &'a str,
    ) -> Self {
        Self {
            secrets_resolver,
            vta_did,
            server_did,
            mediator_did,
        }
    }

    /// Request a URI allocation from the WebVH server.
    pub async fn request_uri(
        &self,
        path: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        let body = match path {
            Some(p) => serde_json::json!({ "path": p }),
            None => serde_json::json!({}),
        };

        let response = self
            .send_and_receive(MSG_DID_REQUEST, body, MSG_DID_OFFER)
            .await?;

        serde_json::from_value(response.body).map_err(|e| {
            AppError::Internal(format!("failed to parse did/offer response: {e}"))
        })
    }

    /// Publish a DID log to the WebVH server.
    pub async fn publish_did(
        &self,
        mnemonic: &str,
        log_content: &str,
    ) -> Result<(), AppError> {
        let body = serde_json::json!({
            "mnemonic": mnemonic,
            "did_log": log_content,
        });

        self.send_and_receive(MSG_DID_PUBLISH, body, MSG_DID_CONFIRM)
            .await?;
        Ok(())
    }

    /// Delete a DID from the WebVH server.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        let body = serde_json::json!({ "mnemonic": mnemonic });

        self.send_and_receive(MSG_DELETE, body, MSG_DELETE_CONFIRM)
            .await?;
        Ok(())
    }

    /// Send a DIDComm message to the WebVH server and wait for a response.
    ///
    /// Creates a short-lived ATM, connects via the mediator, sends the message,
    /// and waits up to 30 seconds for a reply matching the thread ID.
    async fn send_and_receive(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        expected_type: &str,
    ) -> Result<Message, AppError> {
        // 1. Create short-lived TDK state and copy VTA secrets
        let tdk = TDKSharedState::default().await;

        let signing_id = format!("{}#key-0", self.vta_did);
        let ka_id = format!("{}#key-1", self.vta_did);

        if let Some(secret) = self.secrets_resolver.get_secret(&signing_id).await {
            tdk.secrets_resolver.insert(secret).await;
        } else {
            return Err(AppError::Internal(
                "VTA signing secret not available for DIDComm".into(),
            ));
        }

        if let Some(secret) = self.secrets_resolver.get_secret(&ka_id).await {
            tdk.secrets_resolver.insert(secret).await;
        } else {
            return Err(AppError::Internal(
                "VTA key-agreement secret not available for DIDComm".into(),
            ));
        }

        // 2. Create ATM with inbound message channel
        let atm_config = ATMConfig::builder()
            .with_inbound_message_channel(10)
            .build()
            .map_err(|e| AppError::Internal(format!("failed to build ATM config: {e}")))?;

        let atm = ATM::new(atm_config, Arc::new(tdk))
            .await
            .map_err(|e| AppError::Internal(format!("failed to create ATM: {e}")))?;

        // 3. Create profile with mediator
        let profile = ATMProfile::new(
            &atm,
            None,
            self.vta_did.to_string(),
            Some(self.mediator_did.to_string()),
        )
        .await
        .map_err(|e| AppError::Internal(format!("failed to create ATM profile: {e}")))?;
        let profile = Arc::new(profile);

        // 4. Enable WebSocket
        atm.profile_enable_websocket(&profile)
            .await
            .map_err(|e| AppError::Internal(format!("failed to enable websocket: {e}")))?;

        // 5. Build DIDComm message
        let msg_id = uuid::Uuid::new_v4().to_string();
        let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(self.vta_did.to_string())
            .to(self.server_did.to_string())
            .finalize();

        // 6. Pack and send
        let (packed, _) = atm
            .pack_encrypted(
                &msg,
                self.server_did,
                Some(self.vta_did),
                Some(self.vta_did),
                None,
            )
            .await
            .map_err(|e| AppError::Internal(format!("failed to pack message: {e}")))?;

        atm.send_message(&profile, &packed, &msg_id, false, false)
            .await
            .map_err(|e| {
                AppError::Internal(format!("failed to send message to WebVH server: {e}"))
            })?;

        debug!(msg_type, msg_id, server_did = self.server_did, "sent WebVH DIDComm message");

        // 7. Wait for response on inbound channel (30s timeout)
        let mut rx = atm
            .get_inbound_channel()
            .ok_or_else(|| AppError::Internal("no inbound channel available".into()))?;

        let result = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match rx.recv().await {
                    Ok(WebSocketResponses::MessageReceived(resp, _)) => {
                        if resp.thid.as_deref() == Some(&msg_id) {
                            return Ok(*resp);
                        }
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        if let Ok((resp, _)) = atm.unpack(&packed).await
                            && resp.thid.as_deref() == Some(&msg_id)
                        {
                            return Ok(resp);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(AppError::Internal(
                            "inbound channel closed while waiting for WebVH response".into(),
                        ));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            AppError::Internal("timeout waiting for WebVH server DIDComm response".into())
        })?;

        // 8. Graceful shutdown
        atm.graceful_shutdown().await;

        let response = result?;

        // 9. Check for problem report
        if response.type_ == MSG_PROBLEM_REPORT {
            let desc = response
                .body
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("unknown error");
            return Err(AppError::Internal(format!(
                "WebVH server error: {desc}"
            )));
        }

        // 10. Verify expected response type
        if response.type_ != expected_type {
            return Err(AppError::Internal(format!(
                "unexpected response from WebVH server: expected {expected_type}, got {}",
                response.type_
            )));
        }

        debug!(response_type = %response.type_, "received WebVH DIDComm response");
        Ok(response)
    }
}
