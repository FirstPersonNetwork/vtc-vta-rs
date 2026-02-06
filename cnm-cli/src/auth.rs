use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::{Message, PackEncryptedOptions};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

const SERVICE_NAME: &str = "cnm-cli";

// Keyring entry names
const KEY_CLIENT_DID: &str = "client_did";
const KEY_PRIVATE_KEY: &str = "private_key";
const KEY_VTA_DID: &str = "vta_did";
const KEY_ACCESS_TOKEN: &str = "access_token";
const KEY_ACCESS_EXPIRES_AT: &str = "access_expires_at";

#[derive(Debug, Deserialize)]
struct CredentialBundle {
    did: String,
    #[serde(rename = "privateKeyMultibase")]
    private_key_multibase: String,
    #[serde(rename = "vtaDid")]
    vta_did: String,
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

fn keyring_entry(key: &str) -> keyring::Entry {
    keyring::Entry::new(SERVICE_NAME, key).expect("failed to create keyring entry")
}

fn keyring_get(key: &str) -> Option<String> {
    match keyring_entry(key).get_password() {
        Ok(v) => Some(v),
        Err(keyring::Error::NoEntry) => None,
        Err(e) => {
            eprintln!("Warning: keyring read error for {key}: {e}");
            None
        }
    }
}

fn keyring_set(key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    keyring_entry(key)
        .set_password(value)
        .map_err(|e| format!("failed to store {key} in keyring: {e}"))?;
    Ok(())
}

fn keyring_delete(key: &str) {
    let _ = keyring_entry(key).delete_credential();
}

/// Import a base64-encoded credential into the OS keyring.
pub async fn login(credential_b64: &str, base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_json = BASE64
        .decode(credential_b64)
        .map_err(|e| format!("invalid base64 credential: {e}"))?;
    let bundle: CredentialBundle = serde_json::from_slice(&bundle_json)
        .map_err(|e| format!("invalid credential format: {e}"))?;

    // Store in keyring
    keyring_set(KEY_CLIENT_DID, &bundle.did)?;
    keyring_set(KEY_PRIVATE_KEY, &bundle.private_key_multibase)?;
    keyring_set(KEY_VTA_DID, &bundle.vta_did)?;

    // Clear any cached tokens
    keyring_delete(KEY_ACCESS_TOKEN);
    keyring_delete(KEY_ACCESS_EXPIRES_AT);

    println!("Credential imported:");
    println!("  Client DID: {}", bundle.did);
    println!("  VTA DID:    {}", bundle.vta_did);

    // Test authentication
    println!("\nAuthenticating...");
    let token = do_challenge_response(
        base_url,
        &bundle.did,
        &bundle.private_key_multibase,
        &bundle.vta_did,
    )
    .await?;

    // Cache the token
    cache_token(&token.access_token, token.access_expires_at)?;

    println!("Authentication successful.");
    Ok(())
}

/// Clear stored credentials and cached tokens.
pub fn logout() {
    keyring_delete(KEY_CLIENT_DID);
    keyring_delete(KEY_PRIVATE_KEY);
    keyring_delete(KEY_VTA_DID);
    keyring_delete(KEY_ACCESS_TOKEN);
    keyring_delete(KEY_ACCESS_EXPIRES_AT);
    println!("Logged out. Credentials and tokens removed.");
}

/// Show current authentication status.
pub fn status() {
    let client_did = keyring_get(KEY_CLIENT_DID);
    let vta_did = keyring_get(KEY_VTA_DID);
    let access_token = keyring_get(KEY_ACCESS_TOKEN);
    let access_expires = keyring_get(KEY_ACCESS_EXPIRES_AT);

    match &client_did {
        Some(did) => {
            println!("Client DID: {did}");
            println!("VTA DID:    {}", vta_did.as_deref().unwrap_or("(not set)"));

            match (&access_token, &access_expires) {
                (Some(_), Some(exp)) => {
                    let exp_ts: u64 = exp.parse().unwrap_or(0);
                    let now = now_epoch();
                    if exp_ts > now {
                        println!("Token:      valid (expires in {}s)", exp_ts - now);
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
pub async fn ensure_authenticated(
    base_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client_did = keyring_get(KEY_CLIENT_DID).ok_or(
        "Not authenticated.\n\nTo authenticate, import a credential from your VTA administrator:\n  cnm auth login <credential-string>",
    )?;
    let private_key = keyring_get(KEY_PRIVATE_KEY).ok_or("Credential incomplete: missing private key. Re-import with: cnm auth login <credential>")?;
    let vta_did = keyring_get(KEY_VTA_DID).ok_or("Credential incomplete: missing VTA DID. Re-import with: cnm auth login <credential>")?;

    // Check cached token
    if let (Some(token), Some(expires_str)) =
        (keyring_get(KEY_ACCESS_TOKEN), keyring_get(KEY_ACCESS_EXPIRES_AT))
    {
        if let Ok(expires_at) = expires_str.parse::<u64>() {
            if now_epoch() + 30 < expires_at {
                return Ok(token);
            }
        }
    }

    // Full challenge-response
    let result =
        do_challenge_response(base_url, &client_did, &private_key, &vta_did).await?;
    cache_token(&result.access_token, result.access_expires_at)?;

    Ok(result.access_token)
}

struct TokenResult {
    access_token: String,
    access_expires_at: u64,
}

fn cache_token(token: &str, expires_at: u64) -> Result<(), Box<dyn std::error::Error>> {
    keyring_set(KEY_ACCESS_TOKEN, token)?;
    keyring_set(KEY_ACCESS_EXPIRES_AT, &expires_at.to_string())?;
    Ok(())
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
