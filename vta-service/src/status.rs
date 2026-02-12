use std::path::PathBuf;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use crate::acl::{self, Role};
use crate::auth::session::{self, SessionState};
use crate::config::AppConfig;
use crate::contexts;
use crate::keys::{KeyRecord, KeyStatus, KeyType};
use crate::store::Store;

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
    eprintln!(
        "VTA DID:   {}",
        config.vta_did.as_deref().unwrap_or("(not set)")
    );
    eprintln!(
        "URL:       {}",
        config.public_url.as_deref().unwrap_or("(not set)")
    );
    eprintln!("Store:     {}", config.store.data_dir.display());

    // 2. Open store
    let store = Store::open(&config.store)?;
    let contexts_ks = store.keyspace("contexts")?;
    let keys_ks = store.keyspace("keys")?;
    let acl_ks = store.keyspace("acl")?;
    let sessions_ks = store.keyspace("sessions")?;

    // 3. Gather stats

    // --- Contexts ---
    let ctx_records = contexts::list_contexts(&contexts_ks).await?;
    eprintln!();
    eprintln!("--- Contexts ({}) ---", ctx_records.len());

    // Initialize DID resolver for resolution checks
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok();

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
