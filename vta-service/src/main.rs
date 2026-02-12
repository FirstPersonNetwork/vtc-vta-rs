mod acl;
mod acl_cli;
mod auth;
mod config;
mod contexts;
mod did_key;
mod import_did;
#[cfg(feature = "setup")]
mod did_webvh;
mod error;
mod keys;
mod routes;
mod server;
#[cfg(feature = "setup")]
mod setup;
mod status;
mod store;

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use clap::{Parser, Subcommand};
use config::{AppConfig, LogFormat};
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use keys::seed_store::create_seed_store;
use multibase::Base;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "vta", about = "Verified Trust Agent", version)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the interactive setup wizard
    Setup,
    /// Export admin DID and credential
    ExportAdmin,
    /// Show VTA status and statistics
    Status,
    /// Create a did:key in a context (offline, no server required)
    CreateDidKey {
        /// Target context ID
        #[arg(long)]
        context: String,
        /// Also create an ACL entry with Admin role for the new DID
        #[arg(long)]
        admin: bool,
        /// Human-readable label for the key record and ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Create a did:webvh DID for a context (interactive wizard, no server required)
    CreateDidWebvh {
        /// Target context ID
        #[arg(long)]
        context: String,
        /// Human-readable label prefix for key records (default: context id)
        #[arg(long)]
        label: Option<String>,
    },
    /// Import an external DID and create an ACL entry (offline, no server required)
    ImportDid {
        /// The DID to import
        #[arg(long)]
        did: String,
        /// Role to assign (admin, initiator, application)
        #[arg(long)]
        role: Option<String>,
        /// Human-readable label for the ACL entry
        #[arg(long)]
        label: Option<String>,
        /// Restrict to specific context(s); omit for unrestricted access
        #[arg(long)]
        context: Vec<String>,
    },
    /// Manage Access Control List entries (offline, no server required)
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List all ACL entries
    List {
        /// Filter by context
        #[arg(long)]
        context: Option<String>,
        /// Filter by role (admin, initiator, application)
        #[arg(long)]
        role: Option<String>,
    },
    /// Show details of a single ACL entry
    Get {
        /// The DID to look up
        did: String,
    },
    /// Update an existing ACL entry
    Update {
        /// The DID to update
        did: String,
        /// New role (admin, initiator, application)
        #[arg(long)]
        role: Option<String>,
        /// New label (empty string to clear)
        #[arg(long)]
        label: Option<String>,
        /// New context list (comma-separated; omit flag to keep unchanged)
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
    },
    /// Delete an ACL entry
    Delete {
        /// The DID to delete
        did: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Some(Commands::Setup) => {
            #[cfg(feature = "setup")]
            {
                if let Err(e) = setup::run_setup_wizard(cli.config).await {
                    eprintln!("Setup failed: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                eprintln!("Setup wizard not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::ExportAdmin) => {
            if let Err(e) = export_admin(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Status) => {
            if let Err(e) = status::run_status(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidKey {
            context,
            admin,
            label,
        }) => {
            let args = did_key::CreateDidKeyArgs {
                config_path: cli.config,
                context,
                admin,
                label,
            };
            if let Err(e) = did_key::run_create_did_key(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidWebvh { context, label }) => {
            #[cfg(feature = "setup")]
            {
                let args = did_webvh::CreateDidWebvhArgs {
                    config_path: cli.config,
                    context,
                    label,
                };
                if let Err(e) = did_webvh::run_create_did_webvh(args).await {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                let _ = (context, label);
                eprintln!("create-did-webvh is not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::ImportDid {
            did,
            role,
            label,
            context,
        }) => {
            let args = import_did::ImportDidArgs {
                config_path: cli.config,
                did,
                role,
                label,
                context,
            };
            if let Err(e) = import_did::run_import_did(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Acl { command }) => {
            let result = match command {
                AclCommands::List { context, role } => {
                    acl_cli::run_acl_list(cli.config, context, role).await
                }
                AclCommands::Get { did } => acl_cli::run_acl_get(cli.config, did).await,
                AclCommands::Update {
                    did,
                    role,
                    label,
                    contexts,
                } => acl_cli::run_acl_update(cli.config, did, role, label, contexts).await,
                AclCommands::Delete { did, yes } => {
                    acl_cli::run_acl_delete(cli.config, did, yes).await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => {
            let config = match AppConfig::load(cli.config) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error: {e}");
                    eprintln!();
                    eprintln!("To set up a new VTA instance, run:");
                    eprintln!("  vta setup");
                    eprintln!();
                    eprintln!("Or specify a config file:");
                    eprintln!("  vta --config <path>");
                    std::process::exit(1);
                }
            };

            init_tracing(&config);

            let store = store::Store::open(&config.store).expect("failed to open store");
            let seed_store: Arc<dyn keys::seed_store::SeedStore> =
                Arc::from(create_seed_store(&config).expect("failed to create seed store"));

            if let Err(e) = server::run(config, store, seed_store).await {
                tracing::error!("server error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} █████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔══██╗{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}███████║{reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██╔══██║{reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}██║  ██║{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow}╚═╝  ╚═╝{reset}
{dim}  Verified Trust Agent v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

fn init_tracing(config: &AppConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    match config.log.format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Text => subscriber.init(),
    }
}

async fn export_admin(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;
    let keys_ks = store.keyspace("keys")?;
    let seed_store = create_seed_store(&config)?;

    let vta_did = config.vta_did.as_deref().unwrap_or("(not set)");

    // Find admin ACL entries
    let entries = acl::list_acl_entries(&acl_ks).await?;
    let admins: Vec<_> = entries
        .iter()
        .filter(|e| e.role == acl::Role::Admin)
        .collect();

    if admins.is_empty() {
        eprintln!("No admin entries found in ACL.");
        return Ok(());
    }

    eprintln!("VTA DID: {vta_did}");
    if let Some(msg) = &config.messaging {
        eprintln!("Mediator DID: {}", msg.mediator_did);
    }
    eprintln!();

    // Load seed for credential reconstruction
    let seed = seed_store.get().await.map_err(|e| format!("{e}"))?;

    for admin in &admins {
        eprintln!("Admin DID: {}", admin.did);
        if let Some(label) = &admin.label {
            eprintln!("  Label: {label}");
        }

        // For did:key admins, reconstruct the credential
        if admin.did.starts_with("did:key:") {
            if let Some(ref seed) = seed {
                match reconstruct_credential(seed, &admin.did, vta_did, &keys_ks).await {
                    Ok(credential) => {
                        eprintln!();
                        eprintln!("  Credential:");
                        eprintln!("  {credential}");
                    }
                    Err(e) => {
                        eprintln!("  Could not reconstruct credential: {e}");
                    }
                }
            } else {
                eprintln!("  No seed found — cannot reconstruct credential");
            }
        }
        eprintln!();
    }

    Ok(())
}

/// Re-derive the admin private key from BIP-32 seed and build the credential bundle.
async fn reconstruct_credential(
    seed: &[u8],
    admin_did: &str,
    vta_did: &str,
    keys_ks: &store::KeyspaceHandle,
) -> Result<String, Box<dyn std::error::Error>> {
    // The did:key fragment is {did}#{multibase_pubkey}
    let multibase_pubkey = admin_did.strip_prefix("did:key:").unwrap();
    let key_id = format!("{admin_did}#{multibase_pubkey}");

    // Look up the key record to get the derivation path
    let record: keys::KeyRecord = keys_ks
        .get(keys::store_key(&key_id))
        .await?
        .ok_or("admin key record not found in store")?;

    // Re-derive the private key
    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("failed to create BIP-32 root key: {e}"))?;
    let derivation_path: DerivationPath = record
        .derivation_path
        .parse()
        .map_err(|e| format!("invalid derivation path: {e}"))?;
    let derived = root
        .derive(&derivation_path)
        .map_err(|e| format!("key derivation failed: {e}"))?;

    let signing_key = SigningKey::from_bytes(derived.signing_key.as_bytes());
    let private_key_multibase = multibase::encode(Base::Base58Btc, signing_key.as_bytes());

    let bundle = serde_json::json!({
        "did": admin_did,
        "privateKeyMultibase": private_key_multibase,
        "vtaDid": vta_did,
    });
    let bundle_json = serde_json::to_string(&bundle)?;
    Ok(BASE64.encode(bundle_json.as_bytes()))
}
