pub mod auth;
pub mod handlers;
pub mod response;

use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use tokio::sync::{RwLock, broadcast, watch};
use tracing::{info, warn};

use vta_sdk::protocols::{
    acl_management, context_management, credential_management, key_management, seed_management,
    vta_management,
};
#[cfg(feature = "webvh")]
use vta_sdk::protocols::did_management;

use crate::config::AppConfig;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;

const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// Shared state passed to DIDComm message handlers.
pub struct DidcommState {
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: KeyspaceHandle,
    pub seed_store: Arc<dyn SeedStore>,
    pub config: Arc<RwLock<AppConfig>>,
}

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
    state: &DidcommState,
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
                        dispatch_message(atm, profile, vta_did, state, &msg).await;
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => {
                                dispatch_message(atm, profile, vta_did, state, &msg).await;
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

async fn dispatch_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    state: &DidcommState,
    msg: &Message,
) {
    let result = match msg.type_.as_str() {
        TRUST_PING_TYPE => handle_trust_ping(atm, profile, vta_did, msg).await,
        MESSAGE_PICKUP_STATUS_TYPE => Ok(()),

        // Key management
        key_management::CREATE_KEY => {
            handlers::keys::handle_create_key(state, atm, profile, vta_did, msg).await
        }
        key_management::GET_KEY => {
            handlers::keys::handle_get_key(state, atm, profile, vta_did, msg).await
        }
        key_management::LIST_KEYS => {
            handlers::keys::handle_list_keys(state, atm, profile, vta_did, msg).await
        }
        key_management::RENAME_KEY => {
            handlers::keys::handle_rename_key(state, atm, profile, vta_did, msg).await
        }
        key_management::REVOKE_KEY => {
            handlers::keys::handle_revoke_key(state, atm, profile, vta_did, msg).await
        }
        key_management::GET_KEY_SECRET => {
            handlers::keys::handle_get_key_secret(state, atm, profile, vta_did, msg).await
        }

        // Seed management
        seed_management::LIST_SEEDS => {
            handlers::seeds::handle_list_seeds(state, atm, profile, vta_did, msg).await
        }
        seed_management::ROTATE_SEED => {
            handlers::seeds::handle_rotate_seed(state, atm, profile, vta_did, msg).await
        }

        // Context management
        context_management::CREATE_CONTEXT => {
            handlers::contexts::handle_create_context(state, atm, profile, vta_did, msg).await
        }
        context_management::GET_CONTEXT => {
            handlers::contexts::handle_get_context(state, atm, profile, vta_did, msg).await
        }
        context_management::LIST_CONTEXTS => {
            handlers::contexts::handle_list_contexts(state, atm, profile, vta_did, msg).await
        }
        context_management::UPDATE_CONTEXT => {
            handlers::contexts::handle_update_context(state, atm, profile, vta_did, msg).await
        }
        context_management::DELETE_CONTEXT => {
            handlers::contexts::handle_delete_context(state, atm, profile, vta_did, msg).await
        }

        // ACL management
        acl_management::CREATE_ACL => {
            handlers::acl::handle_create_acl(state, atm, profile, vta_did, msg).await
        }
        acl_management::GET_ACL => {
            handlers::acl::handle_get_acl(state, atm, profile, vta_did, msg).await
        }
        acl_management::LIST_ACL => {
            handlers::acl::handle_list_acl(state, atm, profile, vta_did, msg).await
        }
        acl_management::UPDATE_ACL => {
            handlers::acl::handle_update_acl(state, atm, profile, vta_did, msg).await
        }
        acl_management::DELETE_ACL => {
            handlers::acl::handle_delete_acl(state, atm, profile, vta_did, msg).await
        }

        // VTA management
        vta_management::GET_CONFIG => {
            handlers::config::handle_get_config(state, atm, profile, vta_did, msg).await
        }
        vta_management::UPDATE_CONFIG => {
            handlers::config::handle_update_config(state, atm, profile, vta_did, msg).await
        }

        // Credential management
        credential_management::GENERATE_CREDENTIALS => {
            handlers::credentials::handle_generate_credentials(state, atm, profile, vta_did, msg)
                .await
        }

        // DID management (webvh)
        #[cfg(feature = "webvh")]
        did_management::CREATE_DID_WEBVH => {
            handlers::did_webvh::handle_create_did_webvh(state, atm, profile, vta_did, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::GET_DID_WEBVH => {
            handlers::did_webvh::handle_get_did_webvh(state, atm, profile, vta_did, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::LIST_DIDS_WEBVH => {
            handlers::did_webvh::handle_list_dids_webvh(state, atm, profile, vta_did, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::DELETE_DID_WEBVH => {
            handlers::did_webvh::handle_delete_did_webvh(state, atm, profile, vta_did, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::ADD_WEBVH_SERVER => {
            handlers::did_webvh::handle_add_webvh_server(state, atm, profile, vta_did, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::LIST_WEBVH_SERVERS => {
            handlers::did_webvh::handle_list_webvh_servers(state, atm, profile, vta_did, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::REMOVE_WEBVH_SERVER => {
            handlers::did_webvh::handle_remove_webvh_server(state, atm, profile, vta_did, msg)
                .await
        }

        other => {
            warn!(msg_type = other, "unknown message type — ignoring");
            Ok(())
        }
    };

    if let Err(e) = result {
        warn!(msg_type = %msg.type_, error = %e, "handler error");
        if let Some(sender) = msg.from.as_deref() {
            let sender = sender.split('#').next().unwrap_or(sender);
            let _ = response::send_error(
                atm,
                profile,
                vta_did,
                sender,
                Some(&msg.id),
                "e.p.processing",
                &e.to_string(),
            )
            .await;
        }
    }

    // Always delete message from mediator
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
