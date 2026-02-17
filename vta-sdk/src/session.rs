#[cfg(not(any(feature = "keyring", feature = "config-session")))]
compile_error!("enable at least one of: keyring, config-session");

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::{Message, PackEncryptedOptions};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::credentials::CredentialBundle;
use crate::protocols::auth::{AuthenticateResponse, ChallengeRequest, ChallengeResponse};

// ── Session (internal) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    client_did: String,
    private_key: String,
    vta_did: String,
    #[serde(default)]
    vta_url: Option<String>,
    access_token: Option<String>,
    access_expires_at: Option<u64>,
}

// ── Public types ────────────────────────────────────────────────────

/// Loaded session info exposed for health/diagnostics.
pub struct SessionInfo {
    pub client_did: String,
    pub vta_did: String,
    pub private_key_multibase: String,
}

/// Status of a stored session.
pub struct SessionStatus {
    pub client_did: String,
    pub vta_did: String,
    pub vta_url: Option<String>,
    pub token_status: TokenStatus,
}

/// Current state of a cached access token.
pub enum TokenStatus {
    Valid { expires_in_secs: u64 },
    Expired,
    None,
}

/// Result of a successful login.
pub struct LoginResult {
    pub client_did: String,
    pub vta_did: String,
    pub vta_url: Option<String>,
}

pub struct TokenResult {
    pub access_token: String,
    pub access_expires_at: u64,
}

// ── SessionStore ────────────────────────────────────────────────────

/// Reusable session storage for VTA authentication.
///
/// Stores sessions in either the OS keyring or a local JSON file,
/// depending on which feature is enabled.
pub struct SessionStore {
    #[cfg(feature = "keyring")]
    service_name: String,
    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    sessions_dir: PathBuf,
}

impl SessionStore {
    /// Create a new session store.
    ///
    /// - `service_name`: keyring service name (used with `keyring` feature)
    /// - `sessions_dir`: directory for `sessions.json` (used with `config-session` feature)
    pub fn new(service_name: &str, sessions_dir: PathBuf) -> Self {
        // Suppress unused-variable warnings based on active feature
        let _ = &sessions_dir;
        let _ = service_name;

        Self {
            #[cfg(feature = "keyring")]
            service_name: service_name.to_string(),
            #[cfg(all(feature = "config-session", not(feature = "keyring")))]
            sessions_dir,
        }
    }

    // ── Storage backends ────────────────────────────────────────────

    #[cfg(feature = "keyring")]
    fn load(&self, key: &str) -> Option<Session> {
        let entry = keyring::Entry::new(&self.service_name, key).ok()?;
        let json = match entry.get_password() {
            Ok(v) => v,
            Err(keyring::Error::NoEntry) => return None,
            Err(e) => {
                eprintln!("Warning: keyring read error: {e}");
                return None;
            }
        };
        serde_json::from_str(&json).ok()
    }

    #[cfg(feature = "keyring")]
    fn save(&self, key: &str, session: &Session) -> Result<(), Box<dyn std::error::Error>> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| format!("keyring entry error: {e}"))?;
        let json = serde_json::to_string(session)?;
        entry
            .set_password(&json)
            .map_err(|e| format!("failed to store session in keyring: {e}"))?;
        Ok(())
    }

    #[cfg(feature = "keyring")]
    fn clear(&self, key: &str) {
        if let Ok(entry) = keyring::Entry::new(&self.service_name, key) {
            let _ = entry.delete_credential();
        }
    }

    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    fn sessions_path(&self) -> PathBuf {
        self.sessions_dir.join("sessions.json")
    }

    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    fn load_sessions_map(&self) -> std::collections::HashMap<String, Session> {
        let path = self.sessions_path();
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return std::collections::HashMap::new(),
        };
        serde_json::from_str(&data).unwrap_or_default()
    }

    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    fn save_sessions_map(
        &self,
        map: &std::collections::HashMap<String, Session>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.sessions_path();
        let json = serde_json::to_string_pretty(map)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    fn load(&self, key: &str) -> Option<Session> {
        self.load_sessions_map().get(key).cloned()
    }

    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    fn save(&self, key: &str, session: &Session) -> Result<(), Box<dyn std::error::Error>> {
        let mut map = self.load_sessions_map();
        map.insert(key.to_string(), session.clone());
        self.save_sessions_map(&map)
    }

    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    fn clear(&self, key: &str) {
        let mut map = self.load_sessions_map();
        map.remove(key);
        let _ = self.save_sessions_map(&map);
    }

    // ── Public API ──────────────────────────────────────────────────

    /// Returns true if a session exists for the given key.
    pub fn has_session(&self, key: &str) -> bool {
        self.load(key).is_some()
    }

    /// Import a base64-encoded credential and authenticate.
    ///
    /// Returns `LoginResult` on success (no printing).
    pub async fn login(
        &self,
        credential_b64: &str,
        base_url: &str,
        key: &str,
    ) -> Result<LoginResult, Box<dyn std::error::Error>> {
        debug!("decoding credential bundle");
        let bundle = CredentialBundle::decode(credential_b64)
            .map_err(|e| format!("invalid credential: {e}"))?;

        debug!(
            client_did = %bundle.did,
            vta_did = %bundle.vta_did,
            vta_url = ?bundle.vta_url,
            "credential decoded"
        );

        let mut session = Session {
            client_did: bundle.did.clone(),
            private_key: bundle.private_key_multibase.clone(),
            vta_did: bundle.vta_did.clone(),
            vta_url: bundle.vta_url.clone(),
            access_token: None,
            access_expires_at: None,
        };
        self.save(key, &session)?;
        debug!(keyring_key = key, "session saved");

        // Perform authentication
        let token = challenge_response(
            base_url,
            &bundle.did,
            &bundle.private_key_multibase,
            &bundle.vta_did,
        )
        .await?;

        session.access_token = Some(token.access_token);
        session.access_expires_at = Some(token.access_expires_at);
        self.save(key, &session)?;

        Ok(LoginResult {
            client_did: bundle.did,
            vta_did: bundle.vta_did,
            vta_url: bundle.vta_url,
        })
    }

    /// Store a session directly (without performing authentication).
    pub fn store_direct(
        &self,
        key: &str,
        did: &str,
        private_key: &str,
        vta_did: &str,
        vta_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session = Session {
            client_did: did.to_string(),
            private_key: private_key.to_string(),
            vta_did: vta_did.to_string(),
            vta_url: Some(vta_url.to_string()),
            access_token: None,
            access_expires_at: None,
        };
        self.save(key, &session)
    }

    /// Clear stored credentials and cached tokens.
    pub fn logout(&self, key: &str) {
        self.clear(key);
    }

    /// Load the stored session for diagnostics (DID resolution, etc.).
    pub fn loaded_session(&self, key: &str) -> Option<SessionInfo> {
        self.load(key).map(|s| SessionInfo {
            client_did: s.client_did,
            vta_did: s.vta_did,
            private_key_multibase: s.private_key,
        })
    }

    /// Get the status of a stored session.
    pub fn session_status(&self, key: &str) -> Option<SessionStatus> {
        let session = self.load(key)?;
        let token_status = match (session.access_token, session.access_expires_at) {
            (Some(_), Some(exp)) => {
                let now = now_epoch();
                if exp > now {
                    TokenStatus::Valid {
                        expires_in_secs: exp - now,
                    }
                } else {
                    TokenStatus::Expired
                }
            }
            _ => TokenStatus::None,
        };
        Some(SessionStatus {
            client_did: session.client_did,
            vta_did: session.vta_did,
            vta_url: session.vta_url,
            token_status,
        })
    }

    /// Ensure we have a valid access token. Returns the token string.
    ///
    /// If no credentials are stored, returns an error.
    /// If a cached token is still valid (>30s remaining), returns it.
    /// Otherwise, performs a full challenge-response authentication.
    pub async fn ensure_authenticated(
        &self,
        base_url: &str,
        key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        debug!(base_url, keyring_key = key, "ensuring authentication");

        let mut session = self.load(key).ok_or(
            "Not authenticated.\n\nTo authenticate, import a credential:\n  <cli> auth login <credential-string>",
        )?;

        debug!(
            client_did = %session.client_did,
            vta_did = %session.vta_did,
            "session loaded"
        );

        // Check cached token
        if let (Some(token), Some(expires_at)) =
            (&session.access_token, session.access_expires_at)
            && now_epoch() + 30 < expires_at
        {
            debug!(expires_in = expires_at - now_epoch(), "using cached token");
            return Ok(token.clone());
        }

        debug!("cached token expired or missing, performing challenge-response");

        // Full challenge-response
        let result = challenge_response(
            base_url,
            &session.client_did,
            &session.private_key,
            &session.vta_did,
        )
        .await?;

        let token = result.access_token.clone();
        session.access_token = Some(result.access_token);
        session.access_expires_at = Some(result.access_expires_at);
        self.save(key, &session)?;
        debug!("new token cached");

        Ok(token)
    }
}

// ── Challenge-response auth ─────────────────────────────────────────

/// Perform DIDComm challenge-response authentication against a VTA.
pub async fn challenge_response(
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult, Box<dyn std::error::Error>> {
    debug!(
        base_url,
        client_did,
        vta_did,
        "starting challenge-response auth"
    );
    let http = reqwest::Client::new();

    // Step 1: Request challenge
    let challenge_url = format!("{base_url}/auth/challenge");
    debug!(url = %challenge_url, did = client_did, "requesting challenge");
    let challenge_resp = http
        .post(&challenge_url)
        .json(&ChallengeRequest {
            did: client_did.to_string(),
        })
        .send()
        .await?;

    if !challenge_resp.status().is_success() {
        let status = challenge_resp.status();
        let body = challenge_resp.text().await.unwrap_or_default();
        return Err(format!("challenge request failed ({status}): {body}").into());
    }

    let challenge: ChallengeResponse = challenge_resp.json().await?;
    debug!(
        session_id = %challenge.session_id,
        challenge = %challenge.data.challenge,
        "challenge received"
    );

    // Step 2: Build DIDComm message
    debug!("initializing DID resolver");
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    // Build DIDComm secrets from the private key
    let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
    let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;
    debug!(signing_id = %secrets.signing.id, ka_id = %secrets.key_agreement.id, "inserting DIDComm secrets");
    secrets_resolver.insert(secrets.signing).await;
    secrets_resolver.insert(secrets.key_agreement).await;

    // Build the authenticate message
    debug!(
        from = client_did,
        to = vta_did,
        "building DIDComm authenticate message (forward=false)"
    );
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://affinidi.com/atm/1.0/authenticate".to_string(),
        serde_json::json!({
            "challenge": challenge.data.challenge,
            "session_id": challenge.session_id,
        }),
    )
    .from(client_did.to_string())
    .to(vta_did.to_string())
    .finalize();

    // Pack the message (encrypted)
    let (packed, metadata) = msg
        .pack_encrypted(
            vta_did,
            Some(client_did),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions {
                forward: false,
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .map_err(|e| format!("DIDComm pack failed: {e}"))?;

    debug!(
        from_kid = ?metadata.from_kid,
        to_kids = ?metadata.to_kids,
        messaging_service = ?metadata.messaging_service,
        packed_len = packed.len(),
        "message packed"
    );

    // Step 3: Authenticate
    let auth_url = format!("{base_url}/auth/");
    debug!(url = %auth_url, "sending packed message");
    let auth_resp = http
        .post(&auth_url)
        .header("content-type", "text/plain")
        .body(packed)
        .send()
        .await?;

    let status = auth_resp.status();
    debug!(status = %status, "auth response received");

    if !status.is_success() {
        let body = auth_resp.text().await.unwrap_or_default();
        return Err(format!("authentication failed ({status}): {body}").into());
    }

    let auth_data: AuthenticateResponse = auth_resp.json().await?;
    debug!(
        expires_at = auth_data.data.access_expires_at,
        "authentication successful"
    );

    Ok(TokenResult {
        access_token: auth_data.data.access_token,
        access_expires_at: auth_data.data.access_expires_at,
    })
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_round_trip() {
        let session = Session {
            client_did: "did:key:z6Mk1".into(),
            private_key: "z_seed".into(),
            vta_did: "did:key:z6MkVTA".into(),
            vta_url: Some("https://vta.example.com".into()),
            access_token: Some("tok123".into()),
            access_expires_at: Some(1700000000),
        };
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.client_did, session.client_did);
        assert_eq!(restored.private_key, session.private_key);
        assert_eq!(restored.vta_did, session.vta_did);
        assert_eq!(restored.vta_url, session.vta_url);
        assert_eq!(restored.access_token, session.access_token);
        assert_eq!(restored.access_expires_at, session.access_expires_at);
    }

    #[test]
    fn test_session_vta_url_defaults_to_none() {
        let json = r#"{
            "client_did": "did:key:z6Mk1",
            "private_key": "z_seed",
            "vta_did": "did:key:z6MkVTA",
            "access_token": null,
            "access_expires_at": null
        }"#;
        let session: Session = serde_json::from_str(json).unwrap();
        assert!(session.vta_url.is_none());
    }

    #[test]
    fn test_now_epoch_is_recent() {
        let epoch = now_epoch();
        assert!(epoch > 1704067200, "epoch {epoch} should be after 2024");
        assert!(epoch < 4102444800, "epoch {epoch} should be before 2100");
    }
}
