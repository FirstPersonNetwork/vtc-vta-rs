use std::path::PathBuf;

use bip39::Mnemonic;
use dialoguer::{Confirm, Input, Select};
use rand::RngCore;

use crate::config::{AppConfig, LogConfig, LogFormat, MessagingConfig, ServerConfig, StoreConfig};
use crate::keys::seed_store::{KeyringSeedStore, SeedStore};

pub async fn run_setup_wizard() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the VTA setup wizard.\n");

    // 1. Config file path
    let default_path = std::env::var("VTA_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());
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

    // 4. VTA DID
    let vta_did: String = Input::new()
        .with_prompt("VTA DID (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let vta_did = if vta_did.is_empty() {
        None
    } else {
        Some(vta_did)
    };

    // 5. Server host
    let host: String = Input::new()
        .with_prompt("Server host")
        .default("0.0.0.0".into())
        .interact_text()?;

    // 6. Server port
    let port: u16 = Input::new()
        .with_prompt("Server port")
        .default(3000u16)
        .interact_text()?;

    // 7. Log level
    let log_level: String = Input::new()
        .with_prompt("Log level")
        .default("info".into())
        .interact_text()?;

    // 8. Log format
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

    // 9. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/vta".into())
        .interact_text()?;

    // 10. DIDComm messaging
    let messaging = if Confirm::new()
        .with_prompt("Configure DIDComm messaging?")
        .default(false)
        .interact()?
    {
        let mediator_url: String = Input::new().with_prompt("Mediator URL").interact_text()?;
        let mediator_did: String = Input::new().with_prompt("Mediator DID").interact_text()?;
        Some(MessagingConfig {
            mediator_url,
            mediator_did,
        })
    } else {
        None
    };

    // 11. BIP-39 mnemonic
    let mnemonic_options = &["Generate new 24-word mnemonic", "Import existing mnemonic"];
    let mnemonic_choice = Select::new()
        .with_prompt("BIP-39 mnemonic")
        .items(mnemonic_options)
        .default(0)
        .interact()?;

    let mnemonic: Mnemonic = match mnemonic_choice {
        0 => {
            let mut entropy = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut entropy);
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

    // 12. Save config
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
        messaging,
        config_path: config_path.clone(),
    };
    config.save()?;

    // 13. Store seed in OS keyring
    let seed_store = KeyringSeedStore::new("vtc-vta", "master_seed");
    seed_store.set(&mnemonic.to_seed("")).await?;

    // 14. Summary
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    eprintln!("  Config saved to: {}", config_path.display());
    eprintln!("  Seed stored in OS keyring (service: vtc-vta, user: master_seed)");
    if let Some(name) = &config.community_name {
        eprintln!("  Community: {name}");
    }
    eprintln!("  Server: {}:{}", config.server.host, config.server.port);

    Ok(())
}
