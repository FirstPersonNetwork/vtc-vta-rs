use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use dialoguer::{Confirm, Input, Select};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use serde_json::json;

use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};

use crate::config::AppConfig;
use crate::contexts::{self, get_context, store_context};
use crate::keys::seed_store::create_seed_store;
use crate::keys::{self, KeyType as SdkKeyType};
use crate::setup;
use crate::store::Store;

pub struct CreateDidWebvhArgs {
    pub config_path: Option<PathBuf>,
    pub context: String,
    pub label: Option<String>,
}

pub async fn run_create_did_webvh(
    args: CreateDidWebvhArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let contexts_ks = store.keyspace("contexts")?;

    // Load seed from configured backend
    let seed_store = create_seed_store(&config)?;
    let seed = seed_store
        .get()
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or("No seed found. Run `vta setup` first.")?;

    // Resolve context
    let mut ctx = match get_context(&contexts_ks, &args.context).await? {
        Some(ctx) => ctx,
        None => {
            eprintln!("Context '{}' does not exist.", args.context);
            let name: String = Input::new()
                .with_prompt("Create it with name")
                .default(args.context.clone())
                .interact_text()?;
            let ctx = contexts::create_context(&contexts_ks, &args.context, &name).await?;
            eprintln!("Created context: {} ({})", ctx.id, ctx.base_path);
            ctx
        }
    };

    let label = args.label.as_deref().unwrap_or(&args.context);

    // Derive entity keys
    let mut derived = keys::derive_entity_keys(
        &seed,
        &ctx.base_path,
        &format!("{label} signing key"),
        &format!("{label} key-agreement key"),
        &keys_ks,
    )
    .await?;

    // Prompt for URL and convert to WebVHURL
    let webvh_url = setup::prompt_webvh_url(label)?;
    let did_id = webvh_url.to_string();

    // Convert the Signing Key ID to did:key format (required by didwebvh-rs)
    derived.signing_secret.id = [
        "did:key:",
        &derived.signing_secret.get_public_keymultibase().unwrap(),
        "#",
        &derived.signing_secret.get_public_keymultibase().unwrap(),
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
                "publicKeyMultibase": &derived.signing_pub
            }
        ],
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")]
    });

    // Add X25519 key agreement method
    did_document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{did_id}#key-1"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": &derived.ka_pub
        }));
    did_document["keyAgreement"] = json!([format!("{did_id}#key-1")]);

    // Optionally add service endpoints
    if let Some(ref msg) = config.messaging {
        let service_options = &[
            "DIDComm endpoint (references mediator DID for routing)",
            "Mediator service endpoints (#didcomm HTTPS/WSS, #auth)",
            "No service endpoints",
        ];
        let service_choice = Select::new()
            .with_prompt("Service endpoints")
            .items(service_options)
            .default(0)
            .interact()?;

        match service_choice {
            0 => {
                // Reference the mediator DID for routing
                did_document["service"] = json!([
                    {
                        "id": format!("{did_id}#didcomm"),
                        "type": "DIDCommMessaging",
                        "serviceEndpoint": [{
                            "accept": ["didcomm/v2"],
                            "uri": msg.mediator_did
                        }]
                    }
                ]);
            }
            1 => {
                // Mediator-style: #didcomm (HTTPS + WSS) and #auth
                let url = &msg.mediator_url;
                let wss_url = url
                    .replace("https://", "wss://")
                    .replace("http://", "ws://");
                did_document["service"] = json!([
                    {
                        "id": format!("{did_id}#didcomm"),
                        "type": "DIDCommMessaging",
                        "serviceEndpoint": [
                            {
                                "accept": ["didcomm/v2"],
                                "uri": url
                            },
                            {
                                "accept": ["didcomm/v2"],
                                "uri": format!("{wss_url}/ws")
                            }
                        ]
                    },
                    {
                        "id": format!("{did_id}#auth"),
                        "type": "Authentication",
                        "serviceEndpoint": format!("{url}/authenticate")
                    }
                ]);
            }
            _ => {} // No service endpoints
        }
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
    let (next_key_hashes, pre_rotation_keys) =
        setup::prompt_pre_rotation_keys(&seed, &ctx.base_path, label, &keys_ks).await?;

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![derived.signing_pub.clone()])),
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
        .create_log_entry(None, &did_document, &parameters, &derived.signing_secret)
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

    // Save key records now that we have the final DID
    keys::save_entity_key_records(&final_did, &derived, &keys_ks, &ctx.id).await?;

    // Save pre-rotation key records
    for (i, pk) in pre_rotation_keys.iter().enumerate() {
        keys::save_key_record(
            &keys_ks,
            &format!("{final_did}#pre-rotation-{i}"),
            &pk.path,
            SdkKeyType::Ed25519,
            &pk.public_key,
            &pk.label,
            Some(&ctx.id),
        )
        .await?;
    }

    // Update context with the new DID
    ctx.did = Some(final_did.clone());
    ctx.updated_at = Utc::now();
    store_context(&contexts_ks, &ctx)
        .await
        .map_err(|e| format!("{e}"))?;

    // Persist all writes
    store.persist().await?;

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
    eprintln!("  Context '{}' updated with DID: {final_did}", ctx.id);

    // Optionally export secrets bundle
    if Confirm::new()
        .with_prompt("Export DID secrets bundle?")
        .default(false)
        .interact()?
    {
        let bundle = DidSecretsBundle {
            did: final_did.clone(),
            secrets: vec![
                SecretEntry {
                    key_id: format!("{final_did}#key-0"),
                    key_type: SdkKeyType::Ed25519,
                    private_key_multibase: derived.signing_priv.clone(),
                },
                SecretEntry {
                    key_id: format!("{final_did}#key-1"),
                    key_type: SdkKeyType::X25519,
                    private_key_multibase: derived.ka_priv.clone(),
                },
            ],
        };
        let encoded = bundle.encode().map_err(|e| format!("{e}"))?;
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: The secrets bundle contains private keys.      ║");
        eprintln!("║  Store it securely and do not share it publicly.         ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        println!("{encoded}");
        eprintln!();
    }

    Ok(())
}
