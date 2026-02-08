use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::{Message, PackEncryptedOptions};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

const SERVICE_NAME: &str = "cnm-cli";
const KEYRING_KEY: &str = "session";

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

fn load_session() -> Option<Session> {
    let entry = keyring::Entry::new(SERVICE_NAME, KEYRING_KEY).ok()?;
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

fn save_session(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let entry = keyring::Entry::new(SERVICE_NAME, KEYRING_KEY)
        .map_err(|e| format!("keyring entry error: {e}"))?;
    let json = serde_json::to_string(session)?;
    entry
        .set_password(&json)
        .map_err(|e| format!("failed to store session in keyring: {e}"))?;
    Ok(())
}

fn clear_session() {
    if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, KEYRING_KEY) {
        let _ = entry.delete_credential();
    }
}

#[derive(Debug, Deserialize)]
struct CredentialBundle {
    did: String,
    #[serde(rename = "privateKeyMultibase")]
    private_key_multibase: String,
    #[serde(rename = "vtaDid")]
    vta_did: String,
    #[serde(rename = "vtaUrl", default)]
    vta_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct ChallengeRequest {
    did: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    session_id: String,
    data: ChallengeData,
}

#[derive(Debug, Deserialize)]
struct ChallengeData {
    challenge: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateResponse {
    data: AuthenticateData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateData {
    access_token: String,
    access_expires_at: u64,
}

/// Import a base64-encoded credential into the OS keyring.
pub async fn login(credential_b64: &str, base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_json = BASE64
        .decode(credential_b64)
        .map_err(|e| format!("invalid base64 credential: {e}"))?;
    let bundle: CredentialBundle = serde_json::from_slice(&bundle_json)
        .map_err(|e| format!("invalid credential format: {e}"))?;

    let mut session = Session {
        client_did: bundle.did.clone(),
        private_key: bundle.private_key_multibase.clone(),
        vta_did: bundle.vta_did.clone(),
        vta_url: bundle.vta_url.clone(),
        access_token: None,
        access_expires_at: None,
    };
    save_session(&session)?;

    println!("Credential imported:");
    println!("  Client DID: {}", bundle.did);
    println!("  VTA DID:    {}", bundle.vta_did);
    if let Some(ref url) = bundle.vta_url {
        println!("  VTA URL:    {url}");
    }

    // Test authentication
    println!("\nAuthenticating...");
    let token = do_challenge_response(
        base_url,
        &bundle.did,
        &bundle.private_key_multibase,
        &bundle.vta_did,
    )
    .await?;

    session.access_token = Some(token.access_token);
    session.access_expires_at = Some(token.access_expires_at);
    save_session(&session)?;

    println!("Authentication successful.");
    Ok(())
}

/// Clear stored credentials and cached tokens.
pub fn logout() {
    clear_session();
    println!("Logged out. Credentials and tokens removed.");
}

/// Return the stored VTA URL from the session, if any.
pub fn stored_url() -> Option<String> {
    load_session().and_then(|s| s.vta_url)
}

/// Show current authentication status.
pub fn status() {
    match load_session() {
        Some(session) => {
            println!("Client DID: {}", session.client_did);
            println!("VTA DID:    {}", session.vta_did);
            println!(
                "VTA URL:    {}",
                session.vta_url.as_deref().unwrap_or("(not set)")
            );

            match (session.access_token, session.access_expires_at) {
                (Some(_), Some(exp)) => {
                    let now = now_epoch();
                    if exp > now {
                        println!("Token:      valid (expires in {}s)", exp - now);
                    } else {
                        println!("Token:      expired");
                    }
                }
                _ => println!("Token:      none (will authenticate on next request)"),
            }
        }
        None => {
            println!("Not authenticated.");
            println!("\nTo authenticate, import a credential from your VTA administrator:");
            println!("  cnm auth login <credential-string>");
        }
    }
}

/// Ensure we have a valid access token. Returns the token string.
///
/// If no credentials are stored, returns an error prompting the user to log in.
/// If a cached token is still valid (>30s remaining), returns it.
/// Otherwise, performs a full challenge-response authentication.
pub async fn ensure_authenticated(base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut session = load_session().ok_or(
        "Not authenticated.\n\nTo authenticate, import a credential from your VTA administrator:\n  cnm auth login <credential-string>",
    )?;

    // Check cached token
    if let (Some(token), Some(expires_at)) = (&session.access_token, session.access_expires_at)
        && now_epoch() + 30 < expires_at
    {
        return Ok(token.clone());
    }

    // Full challenge-response
    let result = do_challenge_response(
        base_url,
        &session.client_did,
        &session.private_key,
        &session.vta_did,
    )
    .await?;

    let token = result.access_token.clone();
    session.access_token = Some(result.access_token);
    session.access_expires_at = Some(result.access_expires_at);
    save_session(&session)?;

    Ok(token)
}

struct TokenResult {
    access_token: String,
    access_expires_at: u64,
}

async fn do_challenge_response(
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult, Box<dyn std::error::Error>> {
    let http = reqwest::Client::new();

    // Step 1: Request challenge
    let challenge_resp = http
        .post(format!("{base_url}/auth/challenge"))
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

    // Step 2: Build DIDComm message
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    // Decode private key from multibase
    let (_, seed_bytes) = multibase::decode(private_key_multibase)
        .map_err(|e| format!("invalid private key multibase: {e}"))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| "private key seed must be 32 bytes")?;

    // Ed25519 signing secret
    let ed_pub_mb = client_did
        .strip_prefix("did:key:")
        .ok_or("invalid did:key format")?;
    let mut ed_secret = Secret::generate_ed25519(None, Some(&seed));
    ed_secret.id = format!("{client_did}#{ed_pub_mb}");
    secrets_resolver.insert(ed_secret.clone()).await;

    // X25519 key agreement secret (derived from Ed25519)
    let mut x_secret = ed_secret
        .to_x25519()
        .map_err(|e| format!("X25519 conversion failed: {e}"))?;
    let x_pub_mb = x_secret
        .get_public_keymultibase()
        .map_err(|e| format!("failed to get X25519 public key: {e}"))?;
    x_secret.id = format!("{client_did}#{x_pub_mb}");
    secrets_resolver.insert(x_secret).await;

    // Build the authenticate message
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
    let (packed, _metadata) = msg
        .pack_encrypted(
            vta_did,
            Some(client_did),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .map_err(|e| format!("DIDComm pack failed: {e}"))?;

    // Step 3: Authenticate
    let auth_resp = http
        .post(format!("{base_url}/auth/"))
        .header("content-type", "text/plain")
        .body(packed)
        .send()
        .await?;

    if !auth_resp.status().is_success() {
        let status = auth_resp.status();
        let body = auth_resp.text().await.unwrap_or_default();
        return Err(format!("authentication failed ({status}): {body}").into());
    }

    let auth_data: AuthenticateResponse = auth_resp.json().await?;

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

    // ── CredentialBundle deserialization ────────────────────────────

    #[test]
    fn test_credential_bundle_full() {
        let json = r#"{
            "did": "did:key:z6Mk123",
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA",
            "vtaUrl": "https://vta.example.com"
        }"#;
        let bundle: CredentialBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.did, "did:key:z6Mk123");
        assert_eq!(bundle.private_key_multibase, "z1234567890");
        assert_eq!(bundle.vta_did, "did:key:z6MkVTA");
        assert_eq!(bundle.vta_url.as_deref(), Some("https://vta.example.com"));
    }

    #[test]
    fn test_credential_bundle_without_url() {
        let json = r#"{
            "did": "did:key:z6Mk123",
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA"
        }"#;
        let bundle: CredentialBundle = serde_json::from_str(json).unwrap();
        assert!(bundle.vta_url.is_none());
    }

    #[test]
    fn test_credential_bundle_missing_did_fails() {
        let json = r#"{
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA"
        }"#;
        assert!(serde_json::from_str::<CredentialBundle>(json).is_err());
    }

    // ── Session serialization round-trip ───────────────────────────

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
        // Older sessions stored without vta_url should deserialize with None
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

    // ── ChallengeResponse deserialization ──────────────────────────

    #[test]
    fn test_challenge_response_camel_case() {
        let json = r#"{
            "sessionId": "sess-abc",
            "data": { "challenge": "nonce123" }
        }"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id, "sess-abc");
        assert_eq!(resp.data.challenge, "nonce123");
    }

    // ── AuthenticateResponse deserialization ───────────────────────

    #[test]
    fn test_authenticate_response_camel_case() {
        let json = r#"{
            "data": {
                "accessToken": "jwt.token.here",
                "accessExpiresAt": 1700001000
            }
        }"#;
        let resp: AuthenticateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.access_token, "jwt.token.here");
        assert_eq!(resp.data.access_expires_at, 1700001000);
    }

    // ── now_epoch ──────────────────────────────────────────────────

    #[test]
    fn test_now_epoch_is_recent() {
        let epoch = now_epoch();
        // Should be after 2024-01-01 (1704067200) and before 2100-01-01
        assert!(epoch > 1704067200, "epoch {epoch} should be after 2024");
        assert!(epoch < 4102444800, "epoch {epoch} should be before 2100");
    }
}
