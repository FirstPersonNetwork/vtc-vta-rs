use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use crate::config::AppConfig;

const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// Initialize the DIDComm connection to the mediator.
///
/// Connects to the configured mediator over WebSocket and prepares the ATM
/// and profile for inbound message handling.
///
/// Returns `Some((Arc<ATM>, Arc<ATMProfile>))` on success. The caller is
/// responsible for running `run_didcomm_loop` with the returned handles.
pub async fn init_didcomm_connection(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vta_did: &str,
) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
    let messaging = match &config.messaging {
        Some(m) => m,
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            return None;
        }
    };

    // Create TDK shared state and copy VTA secrets from the shared resolver
    let tdk = TDKSharedState::default().await;

    let signing_id = format!("{vta_did}#key-0");
    let ka_id = format!("{vta_did}#key-1");

    if let Some(secret) = secrets_resolver.get_secret(&signing_id).await {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("VTA signing secret not found — messaging disabled");
        return None;
    }

    if let Some(secret) = secrets_resolver.get_secret(&ka_id).await {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("VTA key-agreement secret not found — messaging disabled");
        return None;
    }

    // Build ATM with inbound message channel
    let atm_config = match ATMConfig::builder()
        .with_inbound_message_channel(100)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to build ATM config: {e} — messaging disabled");
            return None;
        }
    };

    let atm = match ATM::new(atm_config, Arc::new(tdk)).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to create ATM: {e} — messaging disabled");
            return None;
        }
    };

    // Create profile with mediator
    let profile = match ATMProfile::new(
        &atm,
        None,
        vta_did.to_string(),
        Some(messaging.mediator_did.clone()),
    )
    .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!("failed to create ATM profile: {e} — messaging disabled");
            return None;
        }
    };

    // Enable WebSocket (auto-starts live streaming from mediator)
    if let Err(e) = atm.profile_enable_websocket(&profile).await {
        warn!("failed to enable websocket: {e} — messaging disabled");
        return None;
    }

    let atm = Arc::new(atm);

    info!("messaging initialized — connected to mediator");
    Some((atm, profile))
}

/// Run the DIDComm inbound message loop until shutdown is signaled.
///
/// Receives messages from the ATM inbound channel and dispatches them to
/// protocol handlers. Exits when `shutdown_rx` fires or the channel closes.
pub async fn run_didcomm_loop(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut rx: broadcast::Receiver<WebSocketResponses> = match atm.get_inbound_channel() {
        Some(rx) => rx,
        None => {
            warn!("no inbound channel available — messaging disabled");
            return;
        }
    };

    info!("DIDComm message loop started");

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _metadata)) => {
                        dispatch_message(atm, profile, vta_did, &msg).await;
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => {
                                dispatch_message(atm, profile, vta_did, &msg).await;
                            }
                            Err(e) => {
                                warn!("failed to unpack inbound message: {e}");
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("inbound message channel lagged, missed {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("inbound message channel closed — stopping message loop");
                        break;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("shutdown signal received — stopping DIDComm message loop");
                break;
            }
        }
    }
}

async fn dispatch_message(atm: &ATM, profile: &Arc<ATMProfile>, vta_did: &str, msg: &Message) {
    match msg.type_.as_str() {
        TRUST_PING_TYPE => {
            if let Err(e) = handle_trust_ping(atm, profile, vta_did, msg).await {
                warn!("failed to handle trust-ping: {e}");
            }
        }
        MESSAGE_PICKUP_STATUS_TYPE => {
            // Mediator status notifications — safe to ignore
        }
        other => {
            warn!(msg_type = other, "unknown message type — ignoring");
        }
    }

    // Always delete the message from the mediator after processing
    if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
        warn!("failed to delete message from mediator: {e}");
    }
}

async fn handle_trust_ping(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    ping: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sender_did = ping
        .from
        .as_deref()
        .ok_or("trust-ping has no 'from' DID — cannot send pong")?;

    info!(from = sender_did, "received trust-ping");

    let pong = TrustPing::default().generate_pong_message(ping, Some(vta_did))?;

    let (packed, _) = atm
        .pack_encrypted(&pong, sender_did, Some(vta_did), Some(vta_did), None)
        .await?;

    atm.send_message(profile, &packed, &pong.id, false, false)
        .await?;

    info!(to = sender_did, "sent trust-pong");
    Ok(())
}
