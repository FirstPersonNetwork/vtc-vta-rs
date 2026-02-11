use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use ed25519_dalek_bip32::ExtendedSigningKey;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::derivation::Bip32Extension;
use crate::keys::seed_store::SeedStore;
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub keys_ks: KeyspaceHandle,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub config: Arc<RwLock<AppConfig>>,
    pub seed_store: Arc<dyn SeedStore>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
}

pub async fn run(
    config: AppConfig,
    store: Store,
    seed_store: Arc<dyn SeedStore>,
) -> Result<(), AppError> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await.map_err(AppError::Io)?;

    // Open cached keyspace handles
    let keys_ks = store.keyspace("keys")?;
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let contexts_ks = store.keyspace("contexts")?;

    // Initialize auth infrastructure
    let (did_resolver, secrets_resolver, jwt_keys) =
        init_auth(&config, &*seed_store, &keys_ks).await;

    let auth_config = config.auth.clone();

    let state = AppState {
        keys_ks,
        sessions_ks,
        acl_ks,
        contexts_ks,
        config: Arc::new(RwLock::new(config)),
        seed_store,
        did_resolver,
        secrets_resolver,
        jwt_keys,
    };

    // Spawn session cleanup background task when auth is configured
    if state.jwt_keys.is_some() {
        tokio::spawn(session_cleanup_loop(state.sessions_ks.clone(), auth_config));
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
    seed_store: &dyn SeedStore,
    keys_ks: &KeyspaceHandle,
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

    // Load seed from store
    let seed = match seed_store.get().await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!("no master seed found — auth endpoints will not work (run setup first)");
            return (None, None, None);
        }
        Err(e) => {
            warn!("failed to load seed: {e} — auth endpoints will not work");
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

    // Look up VTA key paths from stored key records
    let (signing_path, ka_path) = match find_vta_key_paths(&vta_did, keys_ks).await {
        Ok(paths) => paths,
        Err(e) => {
            warn!(
                "failed to find VTA key records: {e} — auth endpoints will not work (run setup first)"
            );
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
    match root.derive_ed25519(&signing_path) {
        Ok(mut signing_secret) => {
            signing_secret.id = format!("{vta_did}#key-0");
            secrets_resolver.insert(signing_secret).await;
        }
        Err(e) => warn!("failed to derive VTA signing key: {e}"),
    }

    // Derive and insert VTA key-agreement secret (X25519)
    match root.derive_x25519(&ka_path) {
        Ok(mut ka_secret) => {
            ka_secret.id = format!("{vta_did}#key-1");
            secrets_resolver.insert(ka_secret).await;
        }
        Err(e) => warn!("failed to derive VTA key-agreement key: {e}"),
    }

    // 3. JWT signing key from config (random key, not BIP-32 derived)
    let jwt_keys = match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None);
            }
        },
        None => {
            warn!(
                "auth.jwt_signing_key not configured — auth endpoints will not work (run setup first)"
            );
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

/// Look up VTA signing and key-agreement derivation paths from stored key records.
///
/// Uses direct lookups by `{vta_did}#key-0` and `{vta_did}#key-1`.
///
/// Returns `(signing_path, ka_path)`.
async fn find_vta_key_paths(
    vta_did: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<(String, String), AppError> {
    let signing_key_id = format!("{vta_did}#key-0");
    let ka_key_id = format!("{vta_did}#key-1");

    let signing: KeyRecord = keys_ks
        .get(crate::keys::store_key(&signing_key_id))
        .await?
        .ok_or_else(|| AppError::NotFound("VTA signing key not found".into()))?;
    let ka: KeyRecord = keys_ks
        .get(crate::keys::store_key(&ka_key_id))
        .await?
        .ok_or_else(|| AppError::NotFound("VTA key-agreement key not found".into()))?;

    debug!(signing_path = %signing.derivation_path, ka_path = %ka.derivation_path, "VTA key paths resolved");
    Ok((signing.derivation_path, ka.derivation_path))
}

/// Decode a base64url-no-pad JWT signing key and construct `JwtKeys`.
fn decode_jwt_key(b64: &str) -> Result<JwtKeys, AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid jwt_signing_key base64: {e}")))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::Config("jwt_signing_key must be exactly 32 bytes".into()))?;
    let keys = JwtKeys::from_ed25519_bytes(&key_bytes)?;
    debug!("JWT signing key decoded successfully");
    Ok(keys)
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
