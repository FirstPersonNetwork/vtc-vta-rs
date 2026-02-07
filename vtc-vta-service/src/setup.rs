use std::path::PathBuf;
use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use bip39::Mnemonic;
use chrono::Utc;
use dialoguer::{Confirm, Input, Select};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use didwebvh_rs::url::WebVHURL;
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use multibase::Base;
use rand::RngCore;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::config::{
    AppConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, ServerConfig, StoreConfig,
};
use crate::keys::seed_store::KeyringSeedStore;
use crate::keys::{KeyRecord, KeyStatus, KeyType as SdkKeyType, store_key};
use crate::store::{KeyspaceHandle, Store};

/// Derivation path for the VTA's Ed25519 signing/verification key.
const VTA_SIGNING_KEY_PATH: &str = "m/44'/0'/0'";

/// Derivation path for the VTA's X25519 key-agreement key.
const VTA_KEY_AGREEMENT_PATH: &str = "m/44'/0'/1'";

/// Base derivation path for VTA pre-rotation keys (`m/44'/1'/N'`).
const VTA_PRE_ROTATION_BASE: &str = "m/44'/1'";

/// Base derivation path for mediator pre-rotation keys (`m/44'/2'/N'`).
const MEDIATOR_PRE_ROTATION_BASE: &str = "m/44'/2'";

/// Base derivation path for admin pre-rotation keys (`m/44'/3'/N'`).
const ADMIN_PRE_ROTATION_BASE: &str = "m/44'/3'";

/// Derivation path for the mediator's Ed25519 signing/verification key.
const MEDIATOR_SIGNING_KEY_PATH: &str = "m/44'/4'/0'";

/// Derivation path for the mediator's X25519 key-agreement key.
const MEDIATOR_KEY_AGREEMENT_PATH: &str = "m/44'/4'/1'";

/// Derivation path for the admin did:webvh Ed25519 signing/verification key.
const ADMIN_SIGNING_KEY_PATH: &str = "m/44'/5'/0'";

/// Derivation path for the admin did:webvh X25519 key-agreement key.
const ADMIN_KEY_AGREEMENT_PATH: &str = "m/44'/5'/1'";

/// Derivation path for the admin did:key Ed25519 key.
const ADMIN_DID_KEY_PATH: &str = "m/44'/5'/2'";

/// Persist a key as a [`KeyRecord`] in the `"keys"` keyspace.
async fn save_key_record(
    keys_ks: &KeyspaceHandle,
    derivation_path: &str,
    key_type: SdkKeyType,
    public_key: &str,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let key_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: derivation_path.to_string(),
        key_type,
        status: KeyStatus::Active,
        public_key: public_key.to_string(),
        label: Some(label.to_string()),
        created_at: now,
        updated_at: now,
    };
    keys_ks.insert(store_key(&key_id), &record).await?;
    Ok(key_id)
}

pub async fn run_setup_wizard(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the VTA setup wizard.\n");

    // 1. Config file path
    let default_path = config_path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            std::env::var("VTA_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into())
        });
    let config_path: String = Input::new()
        .with_prompt("Config file path")
        .default(default_path)
        .interact_text()?;
    let config_path = PathBuf::from(&config_path);

    if config_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                config_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 2. Community name
    let community_name: String = Input::new()
        .with_prompt("Community name (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let community_name = if community_name.is_empty() {
        None
    } else {
        Some(community_name)
    };

    // 3. Community description
    let community_description: String = Input::new()
        .with_prompt("Community description (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let community_description = if community_description.is_empty() {
        None
    } else {
        Some(community_description)
    };

    // 4. Server host
    let host: String = Input::new()
        .with_prompt("Server host")
        .default("0.0.0.0".into())
        .interact_text()?;

    // 5. Server port
    let port: u16 = Input::new()
        .with_prompt("Server port")
        .default(3000u16)
        .interact_text()?;

    // 6. Log level
    let log_level: String = Input::new()
        .with_prompt("Log level")
        .default("info".into())
        .interact_text()?;

    // 7. Log format
    let log_format_items = &["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(log_format_items)
        .default(0)
        .interact()?;
    let log_format = match log_format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 8. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/vta".into())
        .interact_text()?;

    // 9. Open the store so we can persist key records during DID creation
    let store = Store::open(&StoreConfig {
        data_dir: PathBuf::from(&data_dir),
    })?;
    let keys_ks = store.keyspace("keys")?;

    // 10. BIP-39 mnemonic
    let mnemonic_options = &["Generate new 24-word mnemonic", "Import existing mnemonic"];
    let mnemonic_choice = Select::new()
        .with_prompt("BIP-39 mnemonic")
        .items(mnemonic_options)
        .default(0)
        .interact()?;

    let mnemonic: Mnemonic = match mnemonic_choice {
        0 => {
            let mut entropy = [0u8; 32];
            rand::rng().fill_bytes(&mut entropy);
            let m = Mnemonic::from_entropy(&entropy)?;

            eprintln!();
            eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
            eprintln!("║  WARNING: Write down your mnemonic phrase and store it   ║");
            eprintln!("║  securely. It is the ONLY way to recover your keys.      ║");
            eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
            eprintln!();
            eprintln!("\x1b[1m{}\x1b[0m", m);
            eprintln!();

            let confirmed = Confirm::new()
                .with_prompt("I have saved my mnemonic phrase")
                .default(false)
                .interact()?;
            if !confirmed {
                eprintln!("Setup cancelled — please save your mnemonic before proceeding.");
                return Ok(());
            }

            m
        }
        _ => {
            let phrase: String = Input::new()
                .with_prompt("Enter your BIP-39 mnemonic phrase")
                .validate_with(|input: &String| -> Result<(), String> {
                    Mnemonic::parse(input.as_str())
                        .map(|_| ())
                        .map_err(|e| format!("Invalid mnemonic: {e}"))
                })
                .interact_text()?;
            Mnemonic::parse(&phrase)?
        }
    };

    // Store seed in OS keyring
    let seed = mnemonic.to_seed("");
    let seed_store = KeyringSeedStore::new("vtc-vta", "master_seed");
    seed_store.set(&seed).await?;

    // 11. DIDComm messaging (with mediator DID creation)
    let messaging = configure_messaging(&seed, &keys_ks).await?;

    // 12. VTA DID (after mediator so we can embed it as a service endpoint)
    let vta_did = create_vta_did(&seed, &messaging, &keys_ks).await?;

    // 13. Bootstrap admin DID in ACL
    let (admin_did, admin_credential) = create_admin_did(&seed, &vta_did, &keys_ks).await?;

    let acl_ks = store.keyspace("acl")?;
    let admin_entry = AclEntry {
        did: admin_did.clone(),
        role: Role::Admin,
        label: Some("Initial admin".into()),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        created_by: "setup".into(),
    };
    store_acl_entry(&acl_ks, &admin_entry).await?;
    eprintln!("  Admin DID added to ACL: {admin_did}");

    // Flush all store writes to disk before exiting
    store.persist().await?;

    // 14. Save config
    let config = AppConfig {
        vta_did,
        community_name,
        community_description,
        server: ServerConfig { host, port },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(data_dir),
        },
        messaging: Some(messaging),
        auth: AuthConfig::default(),
        config_path: config_path.clone(),
    };
    config.save()?;

    // 15. Summary
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    eprintln!("  Config saved to: {}", config_path.display());
    eprintln!("  Seed stored in OS keyring (service: vtc-vta, user: master_seed)");
    if let Some(name) = &config.community_name {
        eprintln!("  Community: {name}");
    }
    if let Some(did) = &config.vta_did {
        eprintln!("  VTA DID: {did}");
    }
    eprintln!("  Server: {}:{}", config.server.host, config.server.port);
    if let Some(msg) = &config.messaging {
        eprintln!("  Mediator DID: {}", msg.mediator_did);
        eprintln!("  Mediator URL: {}", msg.mediator_url);
    }
    eprintln!("  Admin DID: {admin_did}");
    if let Some(cred) = &admin_credential {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  REMINDER: Save your admin credential string below.      ║");
        eprintln!("║  You will need it to authenticate with the VTA.          ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        eprintln!("  \x1b[1m{cred}\x1b[0m");
        eprintln!();
    }

    Ok(())
}

/// Guide the user through creating or entering an admin DID.
///
/// Returns `(did, Option<credential_string>)`. The credential string is only
/// produced for the `did:key` option (base64-encoded JSON bundle).
async fn create_admin_did(
    seed: &[u8],
    vta_did: &Option<String>,
    keys_ks: &KeyspaceHandle,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let admin_options = &[
        "Generate a new did:key (Ed25519)",
        "Create a new did:webvh DID",
        "Enter an existing DID",
    ];
    let choice = Select::new()
        .with_prompt("Admin DID")
        .items(admin_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            // Derive did:key from BIP-32 seed
            let root = ExtendedSigningKey::from_seed(seed)
                .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;
            let dk_path: DerivationPath = ADMIN_DID_KEY_PATH
                .parse()
                .map_err(|e| format!("Invalid derivation path: {e}"))?;
            let dk_derived = root
                .derive(&dk_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;

            let signing_key = SigningKey::from_bytes(dk_derived.signing_key.as_bytes());
            let public_key = signing_key.verifying_key().to_bytes();

            // Multicodec: ed25519-pub = 0xed, 0x01
            let mut multicodec = Vec::with_capacity(34);
            multicodec.extend_from_slice(&[0xed, 0x01]);
            multicodec.extend_from_slice(&public_key);

            let multibase_pubkey = multibase::encode(Base::Base58Btc, &multicodec);
            let did = format!("did:key:{multibase_pubkey}");
            let private_key_multibase =
                multibase::encode(Base::Base58Btc, dk_derived.signing_key.as_bytes());

            // Save key record
            save_key_record(
                keys_ks,
                ADMIN_DID_KEY_PATH,
                SdkKeyType::Ed25519,
                &multibase_pubkey,
                "Admin did:key",
            )
            .await?;

            // Build credential bundle (same format as POST /auth/credentials)
            let vta_did_str = vta_did.clone().unwrap_or_default();
            let bundle = serde_json::json!({
                "did": did,
                "privateKeyMultibase": private_key_multibase,
                "vtaDid": vta_did_str,
            });
            let bundle_json = serde_json::to_string(&bundle)?;
            let credential = BASE64.encode(bundle_json.as_bytes());

            eprintln!();
            eprintln!("\x1b[1;32mGenerated admin DID:\x1b[0m {did}");
            eprintln!();
            eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
            eprintln!("║  IMPORTANT: Save the credential string below.            ║");
            eprintln!("║  It contains your private key and is the ONLY way to     ║");
            eprintln!("║  authenticate as admin.                                  ║");
            eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
            eprintln!();
            eprintln!("  \x1b[1m{credential}\x1b[0m");
            eprintln!();

            let confirmed = Confirm::new()
                .with_prompt("I have saved the admin credential")
                .default(false)
                .interact()?;
            if !confirmed {
                eprintln!("Setup cancelled — please save your admin credential before proceeding.");
                return Err("Admin credential not saved".into());
            }

            Ok((did, Some(credential)))
        }
        1 => {
            // Create did:webvh for admin with BIP-32 derived keys
            let root = ExtendedSigningKey::from_seed(seed)
                .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;

            let signing_path: DerivationPath = ADMIN_SIGNING_KEY_PATH
                .parse()
                .map_err(|e| format!("Invalid derivation path: {e}"))?;
            let signing_derived = root
                .derive(&signing_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            let mut signing_secret =
                Secret::generate_ed25519(None, Some(signing_derived.signing_key.as_bytes()));

            let ka_path: DerivationPath = ADMIN_KEY_AGREEMENT_PATH
                .parse()
                .map_err(|e| format!("Invalid derivation path: {e}"))?;
            let ka_derived = root
                .derive(&ka_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            let ka_secret = Secret::generate_ed25519(None, Some(ka_derived.signing_key.as_bytes()));
            let ka_secret = ka_secret
                .to_x25519()
                .map_err(|e| format!("X25519 conversion failed: {e}"))?;

            // Save key records
            let signing_pub = signing_secret
                .get_public_keymultibase()
                .map_err(|e| format!("{e}"))?;
            save_key_record(
                keys_ks,
                ADMIN_SIGNING_KEY_PATH,
                SdkKeyType::Ed25519,
                &signing_pub,
                "Admin signing key",
            )
            .await?;

            let ka_pub = ka_secret
                .get_public_keymultibase()
                .map_err(|e| format!("{e}"))?;
            save_key_record(
                keys_ks,
                ADMIN_KEY_AGREEMENT_PATH,
                SdkKeyType::X25519,
                &ka_pub,
                "Admin key-agreement key",
            )
            .await?;

            let did = create_webvh_did(
                &mut signing_secret,
                Some(&ka_secret),
                "admin",
                None,
                seed,
                ADMIN_PRE_ROTATION_BASE,
                keys_ks,
            )
            .await?;
            Ok((did, None))
        }
        _ => {
            // Enter existing DID
            let did: String = Input::new().with_prompt("Admin DID").interact_text()?;
            Ok((did, None))
        }
    }
}

/// Guide the user through creating (or entering) a did:webvh DID for the VTA.
///
/// The mediator is added as a DIDCommMessaging service endpoint in the VTA's
/// DID document.
///
/// Returns `Some(did_string)` or `None` if skipped.
async fn create_vta_did(
    seed: &[u8],
    messaging: &MessagingConfig,
    keys_ks: &KeyspaceHandle,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did_options = &[
        "Create a new did:webvh DID",
        "Enter an existing DID",
        "Skip (no VTA DID for now)",
    ];
    let choice = Select::new()
        .with_prompt("VTA DID")
        .items(did_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            // Derive keys from BIP-32 seed
            let root = ExtendedSigningKey::from_seed(seed)
                .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;

            let signing_path: DerivationPath = VTA_SIGNING_KEY_PATH
                .parse()
                .map_err(|e| format!("Invalid derivation path: {e}"))?;
            let signing_derived = root
                .derive(&signing_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            let mut signing_secret =
                Secret::generate_ed25519(None, Some(signing_derived.signing_key.as_bytes()));

            let ka_path: DerivationPath = VTA_KEY_AGREEMENT_PATH
                .parse()
                .map_err(|e| format!("Invalid derivation path: {e}"))?;
            let ka_derived = root
                .derive(&ka_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            let ka_secret = Secret::generate_ed25519(None, Some(ka_derived.signing_key.as_bytes()));
            let ka_secret = ka_secret
                .to_x25519()
                .map_err(|e| format!("X25519 conversion failed: {e}"))?;

            // Save key records
            let signing_pub = signing_secret
                .get_public_keymultibase()
                .map_err(|e| format!("{e}"))?;
            save_key_record(
                keys_ks,
                VTA_SIGNING_KEY_PATH,
                SdkKeyType::Ed25519,
                &signing_pub,
                "VTA signing key",
            )
            .await?;

            let ka_pub = ka_secret
                .get_public_keymultibase()
                .map_err(|e| format!("{e}"))?;
            save_key_record(
                keys_ks,
                VTA_KEY_AGREEMENT_PATH,
                SdkKeyType::X25519,
                &ka_pub,
                "VTA key-agreement key",
            )
            .await?;

            let did = create_webvh_did(
                &mut signing_secret,
                Some(&ka_secret),
                "VTA",
                Some(messaging),
                seed,
                VTA_PRE_ROTATION_BASE,
                keys_ks,
            )
            .await?;
            Ok(Some(did))
        }
        1 => {
            let did: String = Input::new().with_prompt("VTA DID").interact_text()?;
            Ok(Some(did))
        }
        _ => Ok(None),
    }
}

/// Guide the user through DIDComm messaging configuration.
///
/// Offers to create a new mediator DID or enter an existing one.
async fn configure_messaging(
    seed: &[u8],
    keys_ks: &KeyspaceHandle,
) -> Result<MessagingConfig, Box<dyn std::error::Error>> {
    let mediator_url: String = Input::new().with_prompt("Mediator URL").interact_text()?;

    let mediator_options = &[
        "Create a new did:webvh DID for the mediator",
        "Enter an existing mediator DID",
    ];
    let mediator_choice = Select::new()
        .with_prompt("Mediator DID")
        .items(mediator_options)
        .default(0)
        .interact()?;

    let mediator_did = match mediator_choice {
        0 => {
            let root = ExtendedSigningKey::from_seed(seed)
                .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;

            let signing_path: DerivationPath = MEDIATOR_SIGNING_KEY_PATH
                .parse()
                .map_err(|e| format!("Invalid derivation path: {e}"))?;
            let signing_derived = root
                .derive(&signing_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            let mut signing_secret =
                Secret::generate_ed25519(None, Some(signing_derived.signing_key.as_bytes()));

            let ka_path: DerivationPath = MEDIATOR_KEY_AGREEMENT_PATH
                .parse()
                .map_err(|e| format!("Invalid derivation path: {e}"))?;
            let ka_derived = root
                .derive(&ka_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            let ka_secret = Secret::generate_ed25519(None, Some(ka_derived.signing_key.as_bytes()));
            let ka_secret = ka_secret
                .to_x25519()
                .map_err(|e| format!("X25519 conversion failed: {e}"))?;

            // Save key records
            let signing_pub = signing_secret
                .get_public_keymultibase()
                .map_err(|e| format!("{e}"))?;
            save_key_record(
                keys_ks,
                MEDIATOR_SIGNING_KEY_PATH,
                SdkKeyType::Ed25519,
                &signing_pub,
                "Mediator signing key",
            )
            .await?;

            let ka_pub = ka_secret
                .get_public_keymultibase()
                .map_err(|e| format!("{e}"))?;
            save_key_record(
                keys_ks,
                MEDIATOR_KEY_AGREEMENT_PATH,
                SdkKeyType::X25519,
                &ka_pub,
                "Mediator key-agreement key",
            )
            .await?;

            create_webvh_did(
                &mut signing_secret,
                Some(&ka_secret),
                "mediator",
                None,
                seed,
                MEDIATOR_PRE_ROTATION_BASE,
                keys_ks,
            )
            .await?
        }
        _ => Input::new().with_prompt("Mediator DID").interact_text()?,
    };

    Ok(MessagingConfig {
        mediator_url,
        mediator_did,
    })
}

/// Prompt the user for a URL (e.g. `https://example.com/dids/vta`) and convert
/// it to a [`WebVHURL`].  Re-prompts on invalid input.
fn prompt_webvh_url(label: &str) -> Result<WebVHURL, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Enter the URL where the {label} DID document will be hosted.");
    eprintln!("  Examples:");
    eprintln!("    https://example.com                -> did:webvh:{{SCID}}:example.com");
    eprintln!("    https://example.com/dids/vta       -> did:webvh:{{SCID}}:example.com:dids:vta");
    eprintln!("    http://localhost:8000               -> did:webvh:{{SCID}}:localhost%3A8000");
    eprintln!();

    loop {
        let raw: String = Input::new()
            .with_prompt(format!("{label} DID URL"))
            .default("http://localhost:8000/".into())
            .interact_text()?;

        let parsed = match Url::parse(&raw) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("\x1b[31mInvalid URL: {e} — please try again.\x1b[0m");
                continue;
            }
        };

        match WebVHURL::parse_url(&parsed) {
            Ok(webvh_url) => {
                let did_display = webvh_url.to_string();
                let http_url = webvh_url.get_http_url(None).map_err(|e| format!("{e}"))?;

                eprintln!("  DID:  {did_display}");
                eprintln!("  URL:  {http_url}");

                if Confirm::new()
                    .with_prompt("Is this correct?")
                    .default(true)
                    .interact()?
                {
                    return Ok(webvh_url);
                }
            }
            Err(e) => {
                eprintln!(
                    "\x1b[31mCould not convert to a webvh DID: {e} — please try again.\x1b[0m"
                );
            }
        }
    }
}

/// Prompt the user to optionally generate pre-rotation keys.
///
/// Keys are derived from the BIP-32 seed at `{base_path}/0'`, `{base_path}/1'`,
/// etc. and stored as [`KeyRecord`] entries in the `"keys"` keyspace.
///
/// Returns the list of next-key hashes.  Returns an empty vec when the user
/// declines.
async fn prompt_pre_rotation_keys(
    seed: &[u8],
    base_path: &str,
    label: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Pre-rotation protects against an attacker changing your authorization keys.");
    eprintln!("  You generate future keys now and only publish their hashes.  When you later");
    eprintln!("  need to rotate keys, you reveal the actual key that matches the hash.");

    if !Confirm::new()
        .with_prompt("Enable key pre-rotation?")
        .default(true)
        .interact()?
    {
        return Ok(vec![]);
    }

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;

    let mut hashes: Vec<String> = Vec::new();
    let mut index: u32 = 0;

    loop {
        let path = format!("{base_path}/{index}'");
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| format!("Invalid derivation path: {e}"))?;
        let derived = root
            .derive(&derivation_path)
            .map_err(|e| format!("Key derivation failed: {e}"))?;

        let secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));

        let pub_mb = secret
            .get_public_keymultibase()
            .map_err(|e| format!("{e}"))?;
        let hash = secret
            .get_public_keymultibase_hash()
            .map_err(|e| format!("{e}"))?;

        // Store key record
        let key_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let record = KeyRecord {
            key_id: key_id.clone(),
            derivation_path: path,
            key_type: SdkKeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: pub_mb.clone(),
            label: Some(format!("{label} pre-rotation key {index}")),
            created_at: now,
            updated_at: now,
        };
        keys_ks.insert(store_key(&key_id), &record).await?;

        eprintln!();
        eprintln!("  publicKeyMultibase: {pub_mb}");

        hashes.push(hash);
        index += 1;

        if !Confirm::new()
            .with_prompt(format!(
                "Generated {} pre-rotation key(s). Generate another?",
                hashes.len()
            ))
            .default(false)
            .interact()?
        {
            break;
        }
    }

    Ok(hashes)
}

/// Interactive did:webvh creation flow shared by VTA and mediator DID setup.
///
/// Prompts for a URL, builds a DID document, creates the log entry,
/// and saves the `did.jsonl` file.
///
/// `label` is used in prompts (e.g. "VTA" or "mediator").
/// When `messaging` is provided a DIDCommMessaging service endpoint is added
/// to the DID document.
async fn create_webvh_did(
    signing_secret: &mut Secret,
    ka_secret: Option<&Secret>,
    label: &str,
    messaging: Option<&MessagingConfig>,
    seed: &[u8],
    pre_rotation_base: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<String, Box<dyn std::error::Error>> {
    // Prompt for URL and convert to WebVHURL
    let webvh_url = prompt_webvh_url(label)?;
    let did_id = webvh_url.to_string(); // e.g. did:webvh:{SCID}:example.com

    let pub_key = signing_secret
        .get_public_keymultibase()
        .map_err(|e| format!("Failed to get public key: {e}"))?;

    // Convert the Signing Key ID to be correct
    signing_secret.id = [
        "did:key:",
        &signing_secret.get_public_keymultibase().unwrap(),
        "#",
        &signing_secret.get_public_keymultibase().unwrap(),
    ]
    .concat();

    // Build DID document
    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": &did_id,
        "verificationMethod": [
            {
                "id": format!("{did_id}#key-0"),
                "type": "Multikey",
                "controller": &did_id,
                "publicKeyMultibase": pub_key
            }
        ],
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")]
    });

    // Add X25519 key agreement method if provided
    if let Some(ka) = ka_secret {
        let ka_pub = ka
            .get_public_keymultibase()
            .map_err(|e| format!("Failed to get key-agreement public key: {e}"))?;

        did_document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": format!("{did_id}#key-1"),
                "type": "Multikey",
                "controller": &did_id,
                "publicKeyMultibase": ka_pub
            }));

        did_document["keyAgreement"] = json!([format!("{did_id}#key-1")]);
    }

    // Add DIDCommMessaging service endpoint when a mediator is configured
    if let Some(msg) = messaging {
        did_document["service"] = json!([
            {
                "id": format!("{did_id}#didcomm"),
                "type": "DIDCommMessaging",
                "serviceEndpoint": [{
                    "accept": ["didcomm/v2"],
                    "routingKeys": [msg.mediator_did]
                }]
            }
        ]);
    }

    eprintln!();
    eprintln!(
        "\x1b[2mDID Document:\n{}\x1b[0m",
        serde_json::to_string_pretty(&did_document)?
    );
    eprintln!();

    // Portability
    let portable = Confirm::new()
        .with_prompt("Make this DID portable (can move to a different domain later)?")
        .default(true)
        .interact()?;

    // Pre-rotation keys
    let next_key_hashes = prompt_pre_rotation_keys(seed, pre_rotation_base, label, keys_ks).await?;

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![pub_key])),
        portable: Some(portable),
        next_key_hashes: if next_key_hashes.is_empty() {
            None
        } else {
            Some(Arc::new(next_key_hashes))
        },
        ..Default::default()
    };

    // Create the log entry
    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, signing_secret)
        .map_err(|e| format!("Failed to create DID log entry: {e}"))?;

    let scid = did_state.scid.clone();
    let log_entry_state = did_state.log_entries.last().unwrap();

    let fallback_did = format!("did:webvh:{scid}:{}", webvh_url.domain);
    let final_did = match log_entry_state.log_entry.get_did_document() {
        Ok(doc) => doc
            .get("id")
            .and_then(|id| id.as_str())
            .map(String::from)
            .unwrap_or(fallback_did),
        Err(_) => fallback_did,
    };

    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Save did.jsonl
    let default_file = format!("{label}-did.jsonl");
    let did_file: String = Input::new()
        .with_prompt("Save DID log to file")
        .default(default_file)
        .interact_text()?;

    log_entry_state
        .log_entry
        .save_to_file(&did_file)
        .map_err(|e| format!("Failed to save DID log file: {e}"))?;

    eprintln!("  DID log saved to: {did_file}");

    Ok(final_did)
}
