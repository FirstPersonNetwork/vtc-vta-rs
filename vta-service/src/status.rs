use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use ed25519_dalek_bip32::ExtendedSigningKey;

use crate::acl::{self, Role};
use crate::auth::session::{self, SessionState};
use crate::config::{AppConfig, MessagingConfig};
use crate::contexts;
use crate::keys::derivation::Bip32Extension;
use crate::keys::seed_store::create_seed_store;
use crate::keys::{KeyRecord, KeyStatus, KeyType};
use crate::store::Store;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

pub async fn run_status(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Check setup completion
    let config = match AppConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Setup:     NOT COMPLETE");
            eprintln!("  Error: {e}");
            eprintln!();
            eprintln!("Run `vta setup` to configure this instance.");
            return Ok(());
        }
    };

    eprintln!("=== VTA Status ===");
    eprintln!();
    eprintln!(
        "Name:      {}",
        config.vta_name.as_deref().unwrap_or("(not set)")
    );
    eprintln!(
        "Desc:      {}",
        config.vta_description.as_deref().unwrap_or("(not set)")
    );
    eprintln!("Setup:     complete");
    eprintln!("Config:    {}", config.config_path.display());

    // 2. DID resolver for resolution checks (created early, reused for contexts)
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok();

    // 3. VTA DID + resolution check
    if let Some(ref did) = config.vta_did {
        eprintln!("VTA DID:   {did}");
        if let Some(ref resolver) = did_resolver {
            match resolver.resolve(did).await {
                Ok(_) => {
                    let method = did
                        .strip_prefix("did:")
                        .and_then(|s| s.split(':').next())
                        .unwrap_or("?");
                    eprintln!("           {GREEN}✓{RESET} resolves ({method})");
                }
                Err(e) => eprintln!("           {RED}✗ resolution failed: {e}{RESET}"),
            }
        }
    } else {
        eprintln!("VTA DID:   (not set)");
    }

    // 4. Mediator + resolution check
    if let Some(ref msg) = config.messaging {
        eprintln!("Mediator:  {}", msg.mediator_url);
        eprintln!("           {}", msg.mediator_did);
        if let Some(ref resolver) = did_resolver {
            match resolver.resolve(&msg.mediator_did).await {
                Ok(_) => {
                    let method = msg
                        .mediator_did
                        .strip_prefix("did:")
                        .and_then(|s| s.split(':').next())
                        .unwrap_or("?");
                    eprintln!("           {GREEN}✓{RESET} resolves ({method})");
                }
                Err(e) => eprintln!("           {RED}✗ resolution failed: {e}{RESET}"),
            }
        }
    } else {
        eprintln!("Mediator:  (not configured)");
    }

    eprintln!(
        "URL:       {}",
        config.public_url.as_deref().unwrap_or("(not set)")
    );
    eprintln!("Store:     {}", config.store.data_dir.display());

    // 5. Open store (may fail if VTA is already running)
    let store = match Store::open(&config.store) {
        Ok(s) => s,
        Err(_) => {
            eprintln!();
            eprintln!(
                "Note: Could not open the data store (is VTA already running?)."
            );
            eprintln!(
                "      Stop the VTA service and re-run `vta status` for full statistics."
            );
            eprintln!();
            return Ok(());
        }
    };

    // 6. Trust-ping to mediator (needs secrets from store)
    if let (Some(vta_did), Some(messaging)) = (&config.vta_did, &config.messaging) {
        match tokio::time::timeout(
            Duration::from_secs(10),
            send_trust_ping(&config, &store, vta_did, messaging),
        )
        .await
        {
            Ok(Ok(latency)) => {
                eprintln!("           {GREEN}✓{RESET} pong received ({latency}ms)");
            }
            Ok(Err(e)) => {
                eprintln!("           {RED}✗ trust-ping failed: {e}{RESET}");
            }
            Err(_) => {
                eprintln!("           {RED}✗ trust-ping timed out{RESET}");
            }
        }
    }

    // 7. Gather stats from store
    let contexts_ks = store.keyspace("contexts")?;
    let keys_ks = store.keyspace("keys")?;
    let acl_ks = store.keyspace("acl")?;
    let sessions_ks = store.keyspace("sessions")?;

    // --- Contexts ---
    let ctx_records = contexts::list_contexts(&contexts_ks).await?;
    eprintln!();
    eprintln!("--- Contexts ({}) ---", ctx_records.len());

    for ctx in &ctx_records {
        let did_display = ctx.did.as_deref().unwrap_or("(no DID)");
        let resolution = if let Some(ref did) = ctx.did {
            if let Some(ref resolver) = did_resolver {
                match resolver.resolve(did).await {
                    Ok(_) => {
                        let method = did
                            .strip_prefix("did:")
                            .and_then(|s| s.split(':').next())
                            .unwrap_or("unknown");
                        format!("DID resolution: ok ({method})")
                    }
                    Err(e) => format!("DID resolution: FAILED ({e})"),
                }
            } else {
                "DID resolution: skipped (resolver unavailable)".to_string()
            }
        } else {
            String::new()
        };

        if resolution.is_empty() {
            eprintln!("  {:<16}{}", ctx.id, did_display);
        } else {
            eprintln!("  {:<16}{}   {}", ctx.id, did_display, resolution);
        }
    }

    // --- Keys ---
    let raw_keys = keys_ks.prefix_iter_raw("key:").await?;
    let mut total_keys = 0usize;
    let mut active = 0usize;
    let mut revoked = 0usize;
    let mut ed25519_count = 0usize;
    let mut x25519_count = 0usize;

    for (_key, value) in &raw_keys {
        if let Ok(record) = serde_json::from_slice::<KeyRecord>(value) {
            total_keys += 1;
            match record.status {
                KeyStatus::Active => active += 1,
                KeyStatus::Revoked => revoked += 1,
            }
            match record.key_type {
                KeyType::Ed25519 => ed25519_count += 1,
                KeyType::X25519 => x25519_count += 1,
            }
        }
    }

    eprintln!();
    eprintln!("--- Keys ({total_keys}) ---");
    eprintln!("  Active:  {active}  (Ed25519: {ed25519_count}, X25519: {x25519_count})");
    eprintln!("  Revoked: {revoked}");

    // --- ACL ---
    let acl_entries = acl::list_acl_entries(&acl_ks).await?;
    let admin_count = acl_entries.iter().filter(|e| e.role == Role::Admin).count();
    let initiator_count = acl_entries
        .iter()
        .filter(|e| e.role == Role::Initiator)
        .count();
    let application_count = acl_entries
        .iter()
        .filter(|e| e.role == Role::Application)
        .count();

    eprintln!();
    eprintln!("--- ACL ({}) ---", acl_entries.len());
    eprintln!("  Admin:       {admin_count}");
    eprintln!("  Initiator:   {initiator_count}");
    eprintln!("  Application: {application_count}");

    // --- Sessions ---
    let sessions = session::list_sessions(&sessions_ks).await?;
    let authenticated = sessions
        .iter()
        .filter(|s| s.state == SessionState::Authenticated)
        .count();
    let challenge_sent = sessions
        .iter()
        .filter(|s| s.state == SessionState::ChallengeSent)
        .count();

    eprintln!();
    eprintln!("--- Sessions ({}) ---", sessions.len());
    eprintln!("  Authenticated: {authenticated}");
    eprintln!("  ChallengeSent: {challenge_sent}");
    eprintln!();

    Ok(())
}

/// Send a DIDComm trust-ping to the mediator and return latency in milliseconds.
async fn send_trust_ping(
    config: &AppConfig,
    store: &Store,
    vta_did: &str,
    messaging: &MessagingConfig,
) -> Result<u128, Box<dyn std::error::Error>> {
    // Load seed
    let seed_store = create_seed_store(config)?;
    let seed = seed_store
        .get()
        .await?
        .ok_or("no master seed available")?;

    // Derive BIP-32 root key
    let root = ExtendedSigningKey::from_seed(&seed)?;

    // Look up VTA key derivation paths from store
    let keys_ks = store.keyspace("keys")?;
    let signing_key_id = format!("{vta_did}#key-0");
    let ka_key_id = format!("{vta_did}#key-1");

    let signing: KeyRecord = keys_ks
        .get(crate::keys::store_key(&signing_key_id))
        .await?
        .ok_or("VTA signing key record not found")?;
    let ka: KeyRecord = keys_ks
        .get(crate::keys::store_key(&ka_key_id))
        .await?
        .ok_or("VTA key-agreement key record not found")?;

    // Create TDKSharedState with its own DID resolver + secrets resolver
    let tdk = TDKSharedState::default().await;

    // Insert VTA's Ed25519 signing secret
    let mut signing_secret = root.derive_ed25519(&signing.derivation_path)?;
    signing_secret.id = signing_key_id;
    tdk.secrets_resolver.insert(signing_secret).await;

    // Insert VTA's X25519 key-agreement secret
    let mut ka_secret = root.derive_x25519(&ka.derivation_path)?;
    ka_secret.id = ka_key_id;
    tdk.secrets_resolver.insert(ka_secret).await;

    // Create ATM instance
    let atm_config = ATMConfig::builder().build()?;
    let atm = ATM::new(atm_config, Arc::new(tdk)).await?;

    // Create profile with mediator
    let profile = ATMProfile::new(
        &atm,
        None,
        vta_did.to_string(),
        Some(messaging.mediator_did.clone()),
    )
    .await?;
    let profile = Arc::new(profile);

    // Send trust-ping and measure latency
    let start = Instant::now();
    TrustPing::default()
        .send_ping(
            &atm,
            &profile,
            &messaging.mediator_did,
            true,  // signed
            true,  // expect_pong
            true,  // wait_response
        )
        .await?;
    let elapsed = start.elapsed().as_millis();

    // Clean shutdown
    atm.graceful_shutdown().await;

    Ok(elapsed)
}
