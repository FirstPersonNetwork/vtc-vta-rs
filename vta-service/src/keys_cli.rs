use std::path::PathBuf;

use crate::config::AppConfig;
use crate::keys::derivation::{Bip32Extension, load_or_generate_seed};
use crate::keys::seed_store::create_seed_store;
use crate::keys::{self, KeyRecord, KeyStatus, KeyType};
use crate::store::Store;

pub async fn run_keys_list(
    config_path: Option<PathBuf>,
    context: Option<String>,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let status_filter = status
        .map(|s| match s.as_str() {
            "active" => Ok(KeyStatus::Active),
            "revoked" => Ok(KeyStatus::Revoked),
            _ => Err(format!("unknown status '{s}', expected active or revoked")),
        })
        .transpose()?;

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;

    let raw = keys_ks.prefix_iter_raw("key:").await?;

    let mut records: Vec<KeyRecord> = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if let Some(ref status) = status_filter {
            if record.status != *status {
                continue;
            }
        }
        if let Some(ref ctx) = context {
            if record.context_id.as_deref() != Some(ctx.as_str()) {
                continue;
            }
        }
        records.push(record);
    }

    if records.is_empty() {
        eprintln!("No keys found.");
        return Ok(());
    }

    eprintln!("{} keys:\n", records.len());
    for record in &records {
        print_key_record(record);
    }

    Ok(())
}

pub async fn run_keys_secrets(
    config_path: Option<PathBuf>,
    key_ids: Vec<String>,
    context: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let seed_store = create_seed_store(&config)?;
    let bip32 = load_or_generate_seed(&*seed_store, None)
        .await
        .map_err(|e| format!("{e}"))?;

    // Resolve key IDs: explicit args or all active keys in a context
    let resolved_ids: Vec<String> = if key_ids.is_empty() {
        let ctx = context.as_deref().ok_or(
            "provide key IDs as arguments, or use --context to export all active keys in a context",
        )?;
        let raw = keys_ks.prefix_iter_raw("key:").await?;
        let mut ids = Vec::new();
        for (_key, value) in raw {
            let record: KeyRecord = serde_json::from_slice(&value)?;
            if record.status == KeyStatus::Active
                && record.context_id.as_deref() == Some(ctx)
            {
                ids.push(record.key_id);
            }
        }
        ids
    } else {
        key_ids
    };

    if resolved_ids.is_empty() {
        eprintln!("No active keys found.");
        return Ok(());
    }

    for (i, key_id) in resolved_ids.iter().enumerate() {
        if i > 0 {
            eprintln!();
        }
        let record: KeyRecord = keys_ks
            .get(keys::store_key(key_id))
            .await?
            .ok_or_else(|| format!("key not found: {key_id}"))?;

        let secret = match record.key_type {
            KeyType::Ed25519 => bip32.derive_ed25519(&record.derivation_path),
            KeyType::X25519 => bip32.derive_x25519(&record.derivation_path),
        }
        .map_err(|e| format!("failed to derive key {key_id}: {e}"))?;

        let public = secret
            .get_public_keymultibase()
            .map_err(|e| format!("{e}"))?;
        let private = secret
            .get_private_keymultibase()
            .map_err(|e| format!("{e}"))?;

        eprintln!("Key ID:               {}", record.key_id);
        eprintln!("Key Type:             {}", record.key_type);
        eprintln!("Public Key Multibase: {public}");
        eprintln!("Secret Key Multibase: {private}");
    }

    Ok(())
}

fn print_key_record(record: &KeyRecord) {
    eprintln!("  Key ID:      {}", record.key_id);
    eprintln!("  Key Type:    {}", record.key_type);
    eprintln!("  Path:        {}", record.derivation_path);
    eprintln!("  Status:      {}", record.status);
    if let Some(label) = &record.label {
        eprintln!("  Label:       {label}");
    }
    if let Some(ctx) = &record.context_id {
        eprintln!("  Context:     {ctx}");
    }
    eprintln!("  Created:     {}", record.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
    eprintln!();
}
