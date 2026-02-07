use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::keys::derivation::Bip32Extension;
use crate::keys::paths::{JWT_KEY_PATH, VTA_KEY_AGREEMENT_PATH, VTA_SIGNING_KEY_PATH};
use crate::keys::seed_store::KeyringSeedStore;
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub keys_ks: KeyspaceHandle,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub config: Arc<RwLock<AppConfig>>,
    pub seed_store: Arc<KeyringSeedStore>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
}

pub async fn run(
    config: AppConfig,
    store: Store,
    seed_store: Arc<KeyringSeedStore>,
) -> Result<(), AppError> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await.map_err(AppError::Io)?;

    // Open cached keyspace handles
    let keys_ks = store.keyspace("keys")?;
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;

    // Initialize auth infrastructure
    let (did_resolver, secrets_resolver, jwt_keys) =
        init_auth(&config, &seed_store).await;

    let auth_config = config.auth.clone();

    let state = AppState {
        store,
        keys_ks,
        sessions_ks,
        acl_ks,
        config: Arc::new(RwLock::new(config)),
        seed_store,
        did_resolver,
        secrets_resolver,
        jwt_keys,
    };

    // Spawn session cleanup background task when auth is configured
    if state.jwt_keys.is_some() {
        tokio::spawn(session_cleanup_loop(
            state.sessions_ks.clone(),
            auth_config,
        ));
    }

    let app = routes::router()
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    info!("server listening addr={addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(AppError::Io)?;

    info!("server shut down");
    Ok(())
}

/// Initialize DID resolver, secrets resolver, and JWT keys for authentication.
///
/// Returns `None` values if the VTA DID is not configured (server still starts
/// so the setup wizard can be run first).
async fn init_auth(
    config: &AppConfig,
    seed_store: &KeyringSeedStore,
) -> (
    Option<DIDCacheClient>,
    Option<Arc<ThreadedSecretsResolver>>,
    Option<Arc<JwtKeys>>,
) {
    let vta_did = match &config.vta_did {
        Some(did) => did.clone(),
        None => {
            warn!("vta_did not configured — auth endpoints will not work (run setup first)");
            return (None, None, None);
        }
    };

    // Load seed from keyring
    let seed = match seed_store.get().await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!("no master seed in keyring — auth endpoints will not work (run setup first)");
            return (None, None, None);
        }
        Err(e) => {
            warn!("failed to load seed from keyring: {e} — auth endpoints will not work");
            return (None, None, None);
        }
    };

    let root = match ExtendedSigningKey::from_seed(&seed) {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create BIP-32 root key: {e} — auth endpoints will not work");
            return (None, None, None);
        }
    };

    // 1. DID resolver (local mode)
    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — auth endpoints will not work");
            return (None, None, None);
        }
    };

    // 2. Secrets resolver with VTA's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    // Derive and insert VTA signing secret (Ed25519)
    match root.derive_ed25519(VTA_SIGNING_KEY_PATH) {
        Ok(mut signing_secret) => {
            signing_secret.id = format!("{vta_did}#key-0");
            secrets_resolver.insert(signing_secret).await;
        }
        Err(e) => warn!("failed to derive VTA signing key: {e}"),
    }

    // Derive and insert VTA key-agreement secret (X25519)
    match root.derive_x25519(VTA_KEY_AGREEMENT_PATH) {
        Ok(mut ka_secret) => {
            ka_secret.id = format!("{vta_did}#key-1");
            secrets_resolver.insert(ka_secret).await;
        }
        Err(e) => warn!("failed to derive VTA key-agreement key: {e}"),
    }

    // 3. JWT signing key at dedicated derivation path
    let jwt_keys = match derive_jwt_keys(&root) {
        Ok(k) => k,
        Err(e) => {
            warn!("failed to derive JWT keys: {e} — auth endpoints will not work");
            return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None);
        }
    };

    info!("auth initialized for DID {vta_did}");

    (
        Some(did_resolver),
        Some(Arc::new(secrets_resolver)),
        Some(Arc::new(jwt_keys)),
    )
}

/// Derive JWT signing keys from the BIP-32 root at `m/44'/3'/0'`.
fn derive_jwt_keys(root: &ExtendedSigningKey) -> Result<JwtKeys, AppError> {
    let path: DerivationPath = JWT_KEY_PATH
        .parse()
        .map_err(|e| AppError::KeyDerivation(format!("invalid JWT key path: {e}")))?;
    let derived = root
        .derive(&path)
        .map_err(|e| AppError::KeyDerivation(format!("JWT key derivation failed: {e}")))?;
    JwtKeys::from_ed25519_bytes(derived.signing_key.as_bytes())
}

async fn session_cleanup_loop(sessions_ks: KeyspaceHandle, auth_config: AuthConfig) {
    let interval = Duration::from_secs(auth_config.session_cleanup_interval);
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
            warn!("session cleanup error: {e}");
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
    }
}
