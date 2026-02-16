mod auth;
mod client;
mod config;
mod setup;

use clap::{Parser, Subcommand};
use client::{
    CreateAclRequest, CreateContextRequest, CreateKeyRequest, GenerateCredentialsRequest,
    UpdateAclRequest, UpdateConfigRequest, UpdateContextRequest, VtaClient,
};
use config::{community_keyring_key, resolve_community};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Cell, Row, Table, Widget},
};
use vta_sdk::keys::KeyType;

#[derive(Parser)]
#[command(name = "cnm-cli", about = "CLI for VTC Verifiable Trust Agents")]
struct Cli {
    /// Base URL of the VTA service (overrides config)
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// Override the active community for this command
    #[arg(short = 'c', long, global = true)]
    community: Option<String>,

    /// Enable verbose debug output (can also set RUST_LOG=debug)
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initial setup wizard
    Setup,

    /// Community management
    Community {
        #[command(subcommand)]
        command: CommunityCommands,
    },

    /// Check service health
    Health,

    /// Authentication management
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Key management
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Application context management
    Contexts {
        #[command(subcommand)]
        command: ContextCommands,
    },

    /// Access control list management
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },

    /// Generate auth credentials for applications and services
    AuthCredential {
        #[command(subcommand)]
        command: AuthCredentialCommands,
    },
}

#[derive(Subcommand)]
enum CommunityCommands {
    /// List configured communities
    List,
    /// Switch default community
    Use {
        /// Community slug to set as default
        name: String,
    },
    /// Add a new community
    Add,
    /// Remove a community
    Remove {
        /// Community slug to remove
        name: String,
    },
    /// Show current community info
    Status,
    /// Send a DIDComm trust-ping to the community VTA
    Ping,
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Import a credential and authenticate
    Login {
        /// Base64-encoded credential string from VTA administrator
        credential: String,
    },
    /// Clear stored credentials and tokens
    Logout,
    /// Show current authentication status
    Status,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Get current configuration
    Get,
    /// Update configuration
    Update {
        /// VTA DID
        #[arg(long)]
        community_vta_did: Option<String>,
        /// VTA name
        #[arg(long)]
        community_vta_name: Option<String>,
        /// VTA description
        #[arg(long)]
        community_vta_description: Option<String>,
        /// Public URL for this VTA
        #[arg(long)]
        public_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum ContextCommands {
    /// List all application contexts
    List,
    /// Get a context by ID
    Get {
        /// Context ID (e.g. "vta", "mediator")
        id: String,
    },
    /// Create a new application context
    Create {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
    },
    /// Update an existing context
    Update {
        /// Context ID
        id: String,
        /// New name
        #[arg(long)]
        name: Option<String>,
        /// Set the DID for this context
        #[arg(long)]
        did: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
    },
    /// Delete an application context
    Delete {
        /// Context ID
        id: String,
    },
    /// Create a context and generate credentials for its first admin
    Bootstrap {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Admin label
        #[arg(long)]
        admin_label: Option<String>,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List ACL entries
    List {
        /// Filter by context ID
        #[arg(long)]
        context: Option<String>,
    },
    /// Get an ACL entry by DID
    Get {
        /// DID to look up
        did: String,
    },
    /// Create an ACL entry
    Create {
        /// DID to grant access to
        #[arg(long)]
        did: String,
        /// Role: admin, initiator, or application
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
    },
    /// Update an ACL entry
    Update {
        /// DID of the entry to update
        did: String,
        /// New role
        #[arg(long)]
        role: Option<String>,
        /// New label
        #[arg(long)]
        label: Option<String>,
        /// New comma-separated context IDs
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
    },
    /// Delete an ACL entry
    Delete {
        /// DID of the entry to delete
        did: String,
    },
}

#[derive(Subcommand)]
enum AuthCredentialCommands {
    /// Generate a new auth credential (did:key + ACL entry) for a service or application
    Create {
        /// Role: admin, initiator, or application
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new key
    Create {
        /// Key type: ed25519 or x25519
        #[arg(long)]
        key_type: String,
        /// BIP-32 derivation path (auto-derived from context if omitted)
        #[arg(long)]
        derivation_path: Option<String>,
        /// BIP-39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Application context ID
        #[arg(long)]
        context_id: Option<String>,
    },
    /// Get a key by ID
    Get {
        /// Key ID
        key_id: String,
        /// Reveal private key material (multibase)
        #[arg(long)]
        secret: bool,
    },
    /// Revoke (invalidate) a key
    Revoke {
        /// Key ID
        key_id: String,
    },
    /// Rename a key
    Rename {
        /// Current key ID
        key_id: String,
        /// New key ID
        new_key_id: String,
    },
    /// List all keys
    List {
        /// Maximum number of keys to return
        #[arg(long, default_value = "50")]
        limit: u64,
        /// Number of keys to skip
        #[arg(long, default_value = "0")]
        offset: u64,
        /// Filter by status (active or revoked)
        #[arg(long)]
        status: Option<String>,
    },
}

fn print_banner() {
    let green = "\x1b[32m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{green}  ██████╗ {magenta}███╗   ██╗ {yellow}███╗   ███╗{reset}
{green} ██╔════╝ {magenta}████╗  ██║ {yellow}████╗ ████║{reset}
{green} ██║      {magenta}██╔██╗ ██║ {yellow}██╔████╔██║{reset}
{green} ██║      {magenta}██║╚██╗██║ {yellow}██║╚██╔╝██║{reset}
{green} ╚██████╗ {magenta}██║ ╚████║ {yellow}██║ ╚═╝ ██║{reset}
{green}  ╚═════╝ {magenta}╚═╝  ╚═══╝ {yellow}╚═╝     ╚═╝{reset}
{dim}  Community Network Manager v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Returns true if this command requires authentication.
fn requires_auth(cmd: &Commands) -> bool {
    !matches!(
        cmd,
        Commands::Health | Commands::Auth { .. } | Commands::Setup | Commands::Community { .. }
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing: --verbose sets cnm_cli=debug, or respect RUST_LOG
    let filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("cnm_cli=debug")
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();

    print_banner();

    // Load CNM config (multi-community)
    let cnm_config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config: {e}");
            config::CnmConfig::default()
        }
    };

    // Legacy migration notice
    if cnm_config.communities.is_empty() && auth::has_legacy_session() {
        eprintln!(
            "{YELLOW}Detected legacy single-community session.\n\
             Legacy sessions are no longer used. Run `cnm setup` to configure a community.{RESET}\n"
        );
    }

    // Resolve community URL and keyring key for commands that need a VTA connection.
    // Setup and Community commands handle their own URL resolution.
    let (url, keyring_key): (String, String) = if requires_auth(&cli.command)
        || matches!(cli.command, Commands::Auth { .. })
    {
        // Auth-required and Auth commands always need a community
        match resolve_community(cli.community.as_deref(), &cnm_config) {
            Ok((slug, community)) => {
                let url = cli.url.unwrap_or_else(|| community.url.clone());
                let key = community_keyring_key(&slug);
                (url, key)
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    } else if matches!(cli.command, Commands::Health) {
        // Health: use community if available, otherwise require --url
        match resolve_community(cli.community.as_deref(), &cnm_config) {
            Ok((slug, community)) => {
                let url = cli.url.unwrap_or_else(|| community.url.clone());
                let key = community_keyring_key(&slug);
                (url, key)
            }
            Err(_) => {
                let url = match cli.url {
                    Some(url) => url,
                    None => {
                        eprintln!("Error: no community configured and no --url provided.\n");
                        eprintln!("Either configure a community with `cnm setup`, or provide a URL:");
                        eprintln!("  cnm health --url http://localhost:8100");
                        std::process::exit(1);
                    }
                };
                (url, String::new())
            }
        }
    } else {
        // Setup/Community commands don't need a pre-resolved URL
        let url = cli
            .url
            .unwrap_or_else(|| "http://localhost:8100".to_string());
        (url, String::new())
    };

    let mut client = VtaClient::new(&url);

    // Transparent authentication for protected commands
    if requires_auth(&cli.command) {
        // Bootstrap session from personal VTA if needed
        if auth::loaded_session(&keyring_key).is_none() {
            if let Ok((slug, community)) =
                resolve_community(cli.community.as_deref(), &cnm_config)
                && community.context_id.is_some()
                && let Some(ref personal) = cnm_config.personal_vta
            {
                if let Err(e) =
                    setup::bootstrap_community_session(&slug, community, &personal.url).await
                {
                    eprintln!(
                        "Error: could not bootstrap session from personal VTA: {e}\n\n\
                         To fix this, either:\n  \
                         1. Import a credential: cnm auth login <credential>\n  \
                         2. Re-run setup: cnm setup"
                    );
                    std::process::exit(1);
                }
            }
        }

        match auth::ensure_authenticated(client.base_url(), &keyring_key).await {
            Ok(token) => client.set_token(token),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }

    let result = match cli.command {
        Commands::Setup => setup::run_setup_wizard().await,
        Commands::Community { command } => cmd_community(command, &cnm_config).await,
        Commands::Health => cmd_health(&client, &keyring_key, &cnm_config).await,
        Commands::Auth { command } => match command {
            AuthCommands::Login { credential } => {
                auth::login(&credential, client.base_url(), &keyring_key).await
            }
            AuthCommands::Logout => {
                auth::logout(&keyring_key);
                Ok(())
            }
            AuthCommands::Status => {
                auth::status(&keyring_key);
                Ok(())
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Get => cmd_config_get(&client).await,
            ConfigCommands::Update {
                community_vta_did,
                community_vta_name,
                community_vta_description,
                public_url,
            } => {
                cmd_config_update(
                    &client,
                    community_vta_did,
                    community_vta_name,
                    community_vta_description,
                    public_url,
                )
                .await
            }
        },
        Commands::Contexts { command } => match command {
            ContextCommands::List => cmd_context_list(&client).await,
            ContextCommands::Get { id } => cmd_context_get(&client, &id).await,
            ContextCommands::Create {
                id,
                name,
                description,
            } => cmd_context_create(&client, &id, &name, description).await,
            ContextCommands::Update {
                id,
                name,
                did,
                description,
            } => cmd_context_update(&client, &id, name, did, description).await,
            ContextCommands::Delete { id } => cmd_context_delete(&client, &id).await,
            ContextCommands::Bootstrap {
                id,
                name,
                description,
                admin_label,
            } => cmd_context_bootstrap(&client, &id, &name, description, admin_label).await,
        },
        Commands::Acl { command } => match command {
            AclCommands::List { context } => cmd_acl_list(&client, context.as_deref()).await,
            AclCommands::Get { did } => cmd_acl_get(&client, &did).await,
            AclCommands::Create {
                did,
                role,
                label,
                contexts,
            } => cmd_acl_create(&client, did, role, label, contexts).await,
            AclCommands::Update {
                did,
                role,
                label,
                contexts,
            } => cmd_acl_update(&client, &did, role, label, contexts).await,
            AclCommands::Delete { did } => cmd_acl_delete(&client, &did).await,
        },
        Commands::AuthCredential { command } => match command {
            AuthCredentialCommands::Create {
                role,
                label,
                contexts,
            } => cmd_auth_credential_create(&client, role, label, contexts).await,
        },
        Commands::Keys { command } => match command {
            KeyCommands::Create {
                key_type,
                derivation_path,
                mnemonic,
                label,
                context_id,
            } => {
                cmd_key_create(
                    &client,
                    &key_type,
                    derivation_path,
                    mnemonic,
                    label,
                    context_id,
                )
                .await
            }
            KeyCommands::Get { key_id, secret } => cmd_key_get(&client, &key_id, secret).await,
            KeyCommands::Revoke { key_id } => cmd_key_revoke(&client, &key_id).await,
            KeyCommands::Rename { key_id, new_key_id } => {
                cmd_key_rename(&client, &key_id, &new_key_id).await
            }
            KeyCommands::List {
                limit,
                offset,
                status,
            } => cmd_key_list(&client, offset, limit, status).await,
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_community(
    command: CommunityCommands,
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CommunityCommands::List => {
            if cnm_config.communities.is_empty() {
                println!("No communities configured.");
                println!("\nRun `cnm setup` to configure your first community.");
                return Ok(());
            }
            let default = cnm_config.default_community.as_deref().unwrap_or("");
            for (slug, community) in &cnm_config.communities {
                let marker = if slug == default { " (default)" } else { "" };
                println!("  {slug}{marker}");
                println!("    Name: {}", community.name);
                println!("    URL:  {}", community.url);
                if let Some(ref ctx) = community.context_id {
                    println!("    Context: {ctx}");
                }
                println!();
            }
            Ok(())
        }
        CommunityCommands::Use { name } => {
            if !cnm_config.communities.contains_key(&name) {
                return Err(format!(
                    "community '{name}' not found.\n\nConfigured communities: {}",
                    cnm_config
                        .communities
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into());
            }
            let mut config = config::load_config()?;
            config.default_community = Some(name.clone());
            config::save_config(&config)?;
            println!("Default community set to '{name}'.");
            Ok(())
        }
        CommunityCommands::Add => setup::add_community().await,
        CommunityCommands::Remove { name } => {
            let config = config::load_config()?;
            if !config.communities.contains_key(&name) {
                return Err(format!("community '{name}' not found.").into());
            }

            let confirm = dialoguer::Confirm::new()
                .with_prompt(format!(
                    "Remove community '{name}'? This will delete its stored credentials."
                ))
                .default(false)
                .interact()?;

            if !confirm {
                println!("Cancelled.");
                return Ok(());
            }

            let mut config = config;
            config.communities.remove(&name);
            // Clear default if it was the removed community
            if config.default_community.as_deref() == Some(&name) {
                config.default_community = config.communities.keys().next().cloned();
            }
            // Clear the keyring entry
            auth::logout(&community_keyring_key(&name));
            config::save_config(&config)?;
            println!("Community '{name}' removed.");
            Ok(())
        }
        CommunityCommands::Status => {
            match resolve_community(None, cnm_config) {
                Ok((slug, community)) => {
                    println!("Active community: {slug}");
                    println!("  Name: {}", community.name);
                    println!("  URL:  {}", community.url);
                    if let Some(ref ctx) = community.context_id {
                        println!("  Context: {ctx}");
                    }
                    let key = community_keyring_key(&slug);
                    auth::status(&key);
                }
                Err(_) => {
                    println!("No community configured.");
                    println!("\nRun `cnm setup` to get started.");
                }
            }
            Ok(())
        }
        CommunityCommands::Ping => cmd_community_ping(cnm_config).await,
    }
}

async fn cmd_community_ping(
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use std::time::Duration;

    let (slug, community) = resolve_community(None, cnm_config)?;
    println!("Community: {} ({slug})", community.name);

    // Need a session to get client DID + VTA DID
    let key = community_keyring_key(&slug);
    let session = match auth::loaded_session(&key) {
        Some(s) => s,
        None => {
            return Err("not authenticated — run `cnm auth login` first".into());
        }
    };

    // Check the VTA DID has a DIDCommMessaging service with a mediator
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;

    let resolved = resolver
        .resolve(&session.vta_did)
        .await
        .map_err(|e| format!("failed to resolve VTA DID {}: {e}", session.vta_did))?;

    let mediator_did = resolved
        .doc
        .service
        .iter()
        .filter(|svc| svc.type_.iter().any(|t| t == "DIDCommMessaging"))
        .flat_map(|svc| svc.service_endpoint.get_uris())
        .map(|u| u.trim_matches('"').to_string())
        .find(|u| u.starts_with("did:"));

    let mediator_did = match mediator_did {
        Some(did) => did,
        None => {
            println!("  This community is not using DIDComm Messaging.");
            return Ok(());
        }
    };

    println!("  {CYAN}{:<13}{RESET} {}", "VTA DID", session.vta_did);
    println!("  {CYAN}{:<13}{RESET} {mediator_did}", "Mediator DID");

    print_trust_ping(
        &session,
        &session.vta_did,
        &mediator_did,
        Duration::from_secs(10),
    )
    .await;
    Ok(())
}

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

/// Render a ratatui widget to stdout with ANSI colors.
///
/// This avoids ratatui's `Viewport::Inline` + raw mode, which introduces blank-line
/// gaps between prior output and the table.
fn print_widget(widget: impl Widget, height: u16) {
    let width = ratatui::crossterm::terminal::size().map_or(120, |(w, _)| w);
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    widget.render(area, &mut buf);

    let mut out = String::new();
    for y in 0..height {
        let mut cur_fg = Color::Reset;
        let mut cur_bg = Color::Reset;
        let mut cur_mod = Modifier::empty();

        for x in 0..width {
            let cell = &buf[(x, y)];
            if cell.skip {
                continue;
            }

            if cell.fg != cur_fg || cell.bg != cur_bg || cell.modifier != cur_mod {
                out.push_str("\x1b[0m");
                push_ansi_fg(&mut out, cell.fg);
                push_ansi_bg(&mut out, cell.bg);
                push_ansi_mod(&mut out, cell.modifier);
                cur_fg = cell.fg;
                cur_bg = cell.bg;
                cur_mod = cell.modifier;
            }

            out.push_str(cell.symbol());
        }
        out.push_str("\x1b[0m\n");
    }

    print!("{out}");
}

fn push_ansi_fg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[30m"),
        Color::Red => out.push_str("\x1b[31m"),
        Color::Green => out.push_str("\x1b[32m"),
        Color::Yellow => out.push_str("\x1b[33m"),
        Color::Blue => out.push_str("\x1b[34m"),
        Color::Magenta => out.push_str("\x1b[35m"),
        Color::Cyan => out.push_str("\x1b[36m"),
        Color::Gray => out.push_str("\x1b[37m"),
        Color::DarkGray => out.push_str("\x1b[90m"),
        Color::LightRed => out.push_str("\x1b[91m"),
        Color::LightGreen => out.push_str("\x1b[92m"),
        Color::LightYellow => out.push_str("\x1b[93m"),
        Color::LightBlue => out.push_str("\x1b[94m"),
        Color::LightMagenta => out.push_str("\x1b[95m"),
        Color::LightCyan => out.push_str("\x1b[96m"),
        Color::White => out.push_str("\x1b[97m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[38;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[38;5;{i}m");
        }
    }
}

fn push_ansi_bg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[40m"),
        Color::Red => out.push_str("\x1b[41m"),
        Color::Green => out.push_str("\x1b[42m"),
        Color::Yellow => out.push_str("\x1b[43m"),
        Color::Blue => out.push_str("\x1b[44m"),
        Color::Magenta => out.push_str("\x1b[45m"),
        Color::Cyan => out.push_str("\x1b[46m"),
        Color::Gray => out.push_str("\x1b[47m"),
        Color::DarkGray => out.push_str("\x1b[100m"),
        Color::LightRed => out.push_str("\x1b[101m"),
        Color::LightGreen => out.push_str("\x1b[102m"),
        Color::LightYellow => out.push_str("\x1b[103m"),
        Color::LightBlue => out.push_str("\x1b[104m"),
        Color::LightMagenta => out.push_str("\x1b[105m"),
        Color::LightCyan => out.push_str("\x1b[106m"),
        Color::White => out.push_str("\x1b[107m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[48;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[48;5;{i}m");
        }
    }
}

fn push_ansi_mod(out: &mut String, modifier: Modifier) {
    if modifier.contains(Modifier::BOLD) {
        out.push_str("\x1b[1m");
    }
    if modifier.contains(Modifier::DIM) {
        out.push_str("\x1b[2m");
    }
    if modifier.contains(Modifier::ITALIC) {
        out.push_str("\x1b[3m");
    }
    if modifier.contains(Modifier::UNDERLINED) {
        out.push_str("\x1b[4m");
    }
    if modifier.contains(Modifier::REVERSED) {
        out.push_str("\x1b[7m");
    }
    if modifier.contains(Modifier::CROSSED_OUT) {
        out.push_str("\x1b[9m");
    }
}

fn print_section(title: &str) {
    let pad = 46usize.saturating_sub(title.len());
    println!(
        "\n{DIM}──{RESET} {BOLD}{title}{RESET} {DIM}{}{RESET}",
        "─".repeat(pad)
    );
}

async fn cmd_health(
    client: &VtaClient,
    keyring_key: &str,
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use std::time::Duration;

    let ping_timeout = Duration::from_secs(10);

    // ── Community VTA ──────────────────────────────────────────────
    print_section("Community VTA");

    match client.health().await {
        Ok(resp) => {
            println!(
                "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok (v{})",
                "Service", resp.version
            );
        }
        Err(e) => {
            println!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                "Service"
            );
            // Continue to personal VTA section instead of returning error
            print_personal_vta_section(cnm_config, None, ping_timeout).await;
            return Ok(());
        }
    }
    println!("  {CYAN}{:<13}{RESET} {}", "URL", client.base_url());

    // Create a shared DID resolver for both sections
    let resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => Some(r),
        Err(e) => {
            println!("  {DIM}DID resolution skipped (resolver unavailable: {e}){RESET}");
            None
        }
    };

    // Community DID resolution + trust-ping
    let session = if keyring_key.is_empty() {
        None
    } else {
        auth::loaded_session(keyring_key)
    };
    if let Some(ref session) = session {
        if let Some(ref resolver) = resolver {
            print_did_resolution(resolver, "Client DID", &session.client_did, false).await;

            let mediator_did =
                print_did_resolution(resolver, "VTA DID", &session.vta_did, true).await;

            if let Some(ref mediator_did) = mediator_did {
                print_did_resolution(resolver, "Mediator DID", mediator_did, false).await;
                print_trust_ping(session, mediator_did, mediator_did, ping_timeout).await;
            }
        }
    } else {
        println!("  {DIM}(not authenticated — DID resolution skipped){RESET}");
    }

    // ── Personal VTA ───────────────────────────────────────────────
    print_personal_vta_section(cnm_config, resolver.as_ref(), ping_timeout).await;

    Ok(())
}

async fn print_personal_vta_section(
    cnm_config: &config::CnmConfig,
    resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    ping_timeout: std::time::Duration,
) {
    print_section("Personal VTA");

    let Some(ref personal) = cnm_config.personal_vta else {
        println!("  {DIM}Not configured.{RESET}");
        return;
    };

    let personal_client = VtaClient::new(&personal.url);
    match personal_client.health().await {
        Ok(resp) => {
            println!(
                "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok (v{})",
                "Service", resp.version
            );
        }
        Err(e) => {
            println!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                "Service"
            );
            return;
        }
    };
    println!("  {CYAN}{:<13}{RESET} {}", "URL", personal.url);

    // Personal DID resolution + trust-ping
    let personal_session = auth::loaded_session(config::PERSONAL_KEYRING_KEY);
    if let Some(ref session) = personal_session {
        if let Some(resolver) = resolver {
            print_did_resolution(resolver, "Client DID", &session.client_did, false).await;

            let mediator_did =
                print_did_resolution(resolver, "VTA DID", &session.vta_did, true).await;

            if let Some(ref mediator_did) = mediator_did {
                print_did_resolution(resolver, "Mediator DID", mediator_did, false).await;
                print_trust_ping(session, mediator_did, mediator_did, ping_timeout).await;
            }
        }
    } else {
        println!("  {DIM}(not authenticated — DID resolution skipped){RESET}");
    }
}

/// Resolve a DID and print the result with colored ✓/✗.
///
/// Prints label + DID, then resolution status and detail lines.
/// When `find_mediator` is true, looks for a DIDCommMessaging service and
/// extracts the mediator DID from its endpoint URI (if the URI is a `did:`).
async fn print_did_resolution(
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    label: &str,
    did: &str,
    find_mediator: bool,
) -> Option<String> {
    let method = did
        .strip_prefix("did:")
        .and_then(|s| s.split(':').next())
        .unwrap_or("unknown");

    println!("  {CYAN}{:<13}{RESET} {did}", label);

    let resolved = match resolver.resolve(did).await {
        Ok(r) => r,
        Err(e) => {
            println!("                {RED}✗{RESET} resolution failed: {e}");
            return None;
        }
    };

    println!("                {GREEN}✓{RESET} resolves ({method})");

    for ka in &resolved.doc.key_agreement {
        println!("                {DIM}keyAgreement: {}{RESET}", ka.get_id());
    }

    let mut mediator_did: Option<String> = None;
    for svc in &resolved.doc.service {
        let types = svc.type_.join(", ");
        // Endpoint::get_uris() wraps Map-sourced values in JSON quotes; strip them.
        let uris: Vec<String> = svc
            .service_endpoint
            .get_uris()
            .into_iter()
            .map(|u| u.trim_matches('"').to_string())
            .collect();

        if uris.is_empty() {
            println!("                {DIM}service: {types}{RESET}");
        } else {
            for uri in &uris {
                println!("                {DIM}service: {types} -> {uri}{RESET}");
            }
        }

        if find_mediator
            && svc.type_.iter().any(|t| t == "DIDCommMessaging")
            && mediator_did.is_none()
        {
            mediator_did = uris.into_iter().find(|u| u.starts_with("did:"));
            if let Some(ref m) = mediator_did {
                println!("                mediator {GREEN}✓{RESET} {m}");
            } else {
                println!("                mediator {RED}✗{RESET} no DID found in service endpoint");
            }
        }
    }
    mediator_did
}

/// Send a DIDComm trust-ping and print the result with colored ✓/✗.
///
/// `target_did` is the DID to ping. The message is routed through
/// `mediator_did` (which is also the mediator on the ATM profile).
async fn print_trust_ping(
    session: &auth::SessionInfo,
    target_did: &str,
    mediator_did: &str,
    timeout: std::time::Duration,
) {
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use affinidi_tdk::messaging::profiles::ATMProfile;
    use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
    use affinidi_tdk::secrets_resolver::SecretsResolver;
    use std::sync::Arc;
    use std::time::Instant;

    let client_did = session.client_did.clone();
    let private_key = session.private_key_multibase.clone();
    let mediator = mediator_did.to_string();
    let target = target_did.to_string();

    let ping = async {
        let seed = vta_sdk::did_key::decode_private_key_multibase(&private_key)?;
        let secrets = vta_sdk::did_key::secrets_from_did_key(&client_did, &seed)?;

        let tdk = TDKSharedState::default().await;
        tdk.secrets_resolver.insert(secrets.signing).await;
        tdk.secrets_resolver.insert(secrets.key_agreement).await;

        let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

        let profile = ATMProfile::new(&atm, None, client_did, Some(mediator.clone())).await?;
        let profile = Arc::new(profile);

        // The mediator may only expose a wss:// endpoint (no REST/https).
        atm.profile_enable_websocket(&profile).await?;

        let start = Instant::now();
        TrustPing::default()
            .send_ping(&atm, &profile, &target, true, true, true)
            .await?;
        let elapsed = start.elapsed().as_millis();

        atm.graceful_shutdown().await;
        Ok::<_, Box<dyn std::error::Error>>(elapsed)
    };

    match tokio::time::timeout(timeout, ping).await {
        Ok(Ok(latency)) => println!(
            "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
            "Trust-ping"
        ),
        Ok(Err(e)) => println!(
            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} failed: {e}",
            "Trust-ping"
        ),
        Err(_) => println!(
            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} timed out",
            "Trust-ping"
        ),
    }
}

async fn cmd_config_get(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get_config().await?;
    println!(
        "Community VTA DID:         {}",
        resp.community_vta_did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Community VTA Name:        {}",
        resp.community_vta_name.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Community VTA Description: {}",
        resp.community_vta_description
            .as_deref()
            .unwrap_or("(not set)")
    );
    println!(
        "Community Public URL:      {}",
        resp.public_url.as_deref().unwrap_or("(not set)")
    );
    Ok(())
}

async fn cmd_config_update(
    client: &VtaClient,
    vta_did: Option<String>,
    vta_name: Option<String>,
    vta_description: Option<String>,
    public_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateConfigRequest {
        vta_did,
        vta_name,
        vta_description,
        public_url,
    };
    let resp = client.update_config(req).await?;
    println!("Configuration updated:");
    println!(
        "  Community VTA DID:         {}",
        resp.community_vta_did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Community VTA Name:        {}",
        resp.community_vta_name.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Community VTA Description: {}",
        resp.community_vta_description
            .as_deref()
            .unwrap_or("(not set)")
    );
    println!(
        "  Public URL:      {}",
        resp.public_url.as_deref().unwrap_or("(not set)")
    );
    Ok(())
}

async fn cmd_key_create(
    client: &VtaClient,
    key_type: &str,
    derivation_path: Option<String>,
    mnemonic: Option<String>,
    label: Option<String>,
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        other => {
            return Err(format!("unknown key type '{other}', expected ed25519 or x25519").into());
        }
    };
    let req = CreateKeyRequest {
        key_type,
        derivation_path,
        key_id: None,
        mnemonic,
        label,
        context_id,
    };
    let resp = client.create_key(req).await?;
    println!("Key created:");
    println!("  Key ID:          {}", resp.key_id);
    println!("  Key Type:        {}", resp.key_type);
    println!("  Derivation Path: {}", resp.derivation_path);
    println!("  Public Key:      {}", resp.public_key);
    println!("  Status:          {}", resp.status);
    if let Some(label) = &resp.label {
        println!("  Label:           {label}");
    }
    println!("  Created At:      {}", resp.created_at);
    Ok(())
}

async fn cmd_key_get(
    client: &VtaClient,
    key_id: &str,
    secret: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if secret {
        let resp = client.get_key_secret(key_id).await?;
        println!("Key ID:               {}", resp.key_id);
        println!("Key Type:             {}", resp.key_type);
        println!("Public Key Multibase: {}", resp.public_key_multibase);
        println!("Secret Key Multibase: {}", resp.private_key_multibase);
    } else {
        let resp = client.get_key(key_id).await?;
        println!("Key ID:          {}", resp.key_id);
        println!("Key Type:        {}", resp.key_type);
        println!("Derivation Path: {}", resp.derivation_path);
        println!("Public Key:      {}", resp.public_key);
        println!("Status:          {}", resp.status);
        if let Some(label) = &resp.label {
            println!("Label:           {label}");
        }
        println!("Created At:      {}", resp.created_at);
        println!("Updated At:      {}", resp.updated_at);
    }
    Ok(())
}

async fn cmd_key_revoke(
    client: &VtaClient,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.invalidate_key(key_id).await?;
    println!("Key revoked:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Status:     {}", resp.status);
    println!("  Updated At: {}", resp.updated_at);
    Ok(())
}

async fn cmd_key_rename(
    client: &VtaClient,
    key_id: &str,
    new_key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.rename_key(key_id, new_key_id).await?;
    println!("Key renamed:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Updated At: {}", resp.updated_at);
    Ok(())
}

async fn cmd_key_list(
    client: &VtaClient,
    offset: u64,
    limit: u64,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_keys(offset, limit, status.as_deref()).await?;

    if resp.keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    let end = (offset + resp.keys.len() as u64).min(resp.total);

    let dim = Style::default().fg(Color::DarkGray);
    let bold = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);

    let rows: Vec<Row> = resp
        .keys
        .iter()
        .map(|key| {
            let label = key.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = key.created_at.format("%Y-%m-%d").to_string();

            let status_span = match key.status {
                vta_sdk::keys::KeyStatus::Active => {
                    Span::styled(key.status.to_string(), Style::default().fg(Color::Green))
                }
                vta_sdk::keys::KeyStatus::Revoked => {
                    Span::styled(key.status.to_string(), Style::default().fg(Color::Red))
                }
            };

            let id_line = Line::from(vec![
                Span::styled("\u{25b8} ", Style::default().fg(Color::Cyan)),
                Span::styled(key.key_id.clone(), bold),
            ]);

            let detail_line = Line::from(vec![
                Span::raw("  "),
                Span::styled(label, Style::default().fg(Color::Yellow)),
                Span::styled("  \u{2502}  ", dim),
                Span::raw(key.key_type.to_string()),
                Span::styled("  \u{2502}  ", dim),
                status_span,
                Span::styled("  \u{2502}  ", dim),
                Span::styled(key.derivation_path.clone(), dim),
                Span::styled("  \u{2502}  ", dim),
                Span::styled(created, dim),
            ]);

            Row::new(vec![Cell::from(Text::from(vec![id_line, detail_line]))])
                .height(2)
                .bottom_margin(1)
        })
        .collect();

    let title = format!(" Keys ({}\u{2013}{} of {}) ", offset + 1, end, resp.total);

    let table = Table::new(rows, [Constraint::Min(1)])
        .block(Block::bordered().title(title).border_style(dim));

    // Each key = 2 lines + 1 bottom_margin, last key's margin clipped, + 2 for borders
    let height = (resp.keys.len() as u16 * 3).saturating_sub(1) + 2;
    print_widget(table, height);

    Ok(())
}

// ── ACL commands ────────────────────────────────────────────────────

fn format_contexts(contexts: &[String]) -> String {
    if contexts.is_empty() {
        "(unrestricted)".to_string()
    } else {
        contexts.join(", ")
    }
}

fn format_role(role: &str, contexts: &[String]) -> String {
    if role == "admin" && contexts.is_empty() {
        "super admin".to_string()
    } else {
        role.to_string()
    }
}

fn validate_role(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    match role {
        "admin" | "initiator" | "application" => Ok(()),
        _ => {
            Err(format!("invalid role '{role}', expected: admin, initiator, or application").into())
        }
    }
}

async fn cmd_acl_list(
    client: &VtaClient,
    context: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_acl(context).await?;

    if resp.entries.is_empty() {
        println!("No ACL entries found.");
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["DID", "Role", "Label", "Contexts", "Created By"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .entries
        .iter()
        .map(|entry| {
            let label = entry.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let contexts = format_contexts(&entry.allowed_contexts);

            Row::new(vec![
                Cell::from(entry.did.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(format_role(&entry.role, &entry.allowed_contexts)),
                Cell::from(label),
                Cell::from(contexts),
                Cell::from(entry.created_by.clone()).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" ACL Entries ({}) ", resp.entries.len());

    let table = Table::new(
        rows,
        [
            Constraint::Min(60),    // DID
            Constraint::Length(12), // Role
            Constraint::Min(16),    // Label
            Constraint::Length(24), // Contexts
            Constraint::Length(52), // Created By
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.entries.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

async fn cmd_acl_get(client: &VtaClient, did: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = client.get_acl(did).await?;
    println!("DID:              {}", entry.did);
    println!(
        "Role:             {}",
        format_role(&entry.role, &entry.allowed_contexts)
    );
    println!(
        "Label:            {}",
        entry.label.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Contexts:         {}",
        format_contexts(&entry.allowed_contexts)
    );
    println!("Created At:       {}", entry.created_at);
    println!("Created By:       {}", entry.created_by);
    Ok(())
}

async fn cmd_acl_create(
    client: &VtaClient,
    did: String,
    role: String,
    label: Option<String>,
    contexts: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_role(&role)?;
    let req = CreateAclRequest {
        did,
        role,
        label,
        allowed_contexts: contexts,
    };
    let entry = client.create_acl(req).await?;
    println!("ACL entry created:");
    println!("  DID:      {}", entry.did);
    println!(
        "  Role:     {}",
        format_role(&entry.role, &entry.allowed_contexts)
    );
    if let Some(label) = &entry.label {
        println!("  Label:    {label}");
    }
    println!("  Contexts: {}", format_contexts(&entry.allowed_contexts));
    Ok(())
}

async fn cmd_acl_update(
    client: &VtaClient,
    did: &str,
    role: Option<String>,
    label: Option<String>,
    contexts: Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref r) = role {
        validate_role(r)?;
    }
    let req = UpdateAclRequest {
        role,
        label,
        allowed_contexts: contexts,
    };
    let entry = client.update_acl(did, req).await?;
    println!("ACL entry updated:");
    println!("  DID:      {}", entry.did);
    println!(
        "  Role:     {}",
        format_role(&entry.role, &entry.allowed_contexts)
    );
    if let Some(label) = &entry.label {
        println!("  Label:    {label}");
    }
    println!("  Contexts: {}", format_contexts(&entry.allowed_contexts));
    Ok(())
}

async fn cmd_acl_delete(client: &VtaClient, did: &str) -> Result<(), Box<dyn std::error::Error>> {
    client.delete_acl(did).await?;
    println!("ACL entry deleted: {did}");
    Ok(())
}

// ── Auth credential commands ─────────────────────────────────────────

async fn cmd_auth_credential_create(
    client: &VtaClient,
    role: String,
    label: Option<String>,
    contexts: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_role(&role)?;
    let req = GenerateCredentialsRequest {
        role,
        label,
        allowed_contexts: contexts,
    };
    let resp = client.generate_credentials(req).await?;
    println!("Credentials generated:");
    println!("  DID:  {}", resp.did);
    println!("  Role: {}", resp.role);
    println!();
    println!("Credential (one-time secret — save this now):");
    println!("{}", resp.credential);
    Ok(())
}

// ── Context commands ────────────────────────────────────────────────

async fn cmd_context_bootstrap(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
    admin_label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create the context
    let ctx_req = CreateContextRequest {
        id: id.to_string(),
        name: name.to_string(),
        description,
    };
    let ctx = client.create_context(ctx_req).await?;
    println!("Context created:");
    println!("  ID:        {}", ctx.id);
    println!("  Name:      {}", ctx.name);
    println!("  Base Path: {}", ctx.base_path);

    // 2. Generate credentials for the first admin
    let cred_req = GenerateCredentialsRequest {
        role: "admin".to_string(),
        label: admin_label,
        allowed_contexts: vec![id.to_string()],
    };
    let resp = client.generate_credentials(cred_req).await?;
    println!();
    println!("Admin credential created:");
    println!("  DID:  {}", resp.did);
    println!("  Role: admin");
    println!();
    println!("Credential (one-time secret — save this now):");
    println!("{}", resp.credential);

    Ok(())
}

async fn cmd_context_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_contexts().await?;

    if resp.contexts.is_empty() {
        println!("No contexts found.");
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["ID", "Name", "DID", "Base Path", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .contexts
        .iter()
        .map(|ctx| {
            let did = ctx.did.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = ctx.created_at.format("%Y-%m-%d").to_string();

            Row::new(vec![
                Cell::from(ctx.id.clone()),
                Cell::from(ctx.name.clone()),
                Cell::from(did).style(Style::default().fg(Color::DarkGray)),
                Cell::from(ctx.base_path.clone()),
                Cell::from(created),
            ])
        })
        .collect();

    let title = format!(" Contexts ({}) ", resp.contexts.len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(16), // ID
            Constraint::Min(20),    // Name
            Constraint::Length(30), // DID
            Constraint::Length(16), // Base Path
            Constraint::Length(10), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.contexts.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

async fn cmd_context_get(client: &VtaClient, id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get_context(id).await?;
    println!("ID:          {}", resp.id);
    println!("Name:        {}", resp.name);
    println!(
        "DID:         {}",
        resp.did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Description: {}",
        resp.description.as_deref().unwrap_or("(not set)")
    );
    println!("Base Path:   {}", resp.base_path);
    println!("Created At:  {}", resp.created_at);
    println!("Updated At:  {}", resp.updated_at);
    Ok(())
}

async fn cmd_context_create(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = CreateContextRequest {
        id: id.to_string(),
        name: name.to_string(),
        description,
    };
    let resp = client.create_context(req).await?;
    println!("Context created:");
    println!("  ID:        {}", resp.id);
    println!("  Name:      {}", resp.name);
    println!("  Base Path: {}", resp.base_path);
    Ok(())
}

async fn cmd_context_update(
    client: &VtaClient,
    id: &str,
    name: Option<String>,
    did: Option<String>,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateContextRequest {
        name,
        did,
        description,
    };
    let resp = client.update_context(id, req).await?;
    println!("Context updated:");
    println!("  ID:          {}", resp.id);
    println!("  Name:        {}", resp.name);
    println!(
        "  DID:         {}",
        resp.did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Description: {}",
        resp.description.as_deref().unwrap_or("(not set)")
    );
    println!("  Updated At:  {}", resp.updated_at);
    Ok(())
}

async fn cmd_context_delete(
    client: &VtaClient,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.delete_context(id).await?;
    println!("Context deleted: {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_contexts ────────────────────────────────────────────

    #[test]
    fn test_format_contexts_empty_shows_unrestricted() {
        assert_eq!(format_contexts(&[]), "(unrestricted)");
    }

    #[test]
    fn test_format_contexts_single() {
        let ctx = vec!["vta".to_string()];
        assert_eq!(format_contexts(&ctx), "vta");
    }

    #[test]
    fn test_format_contexts_multiple() {
        let ctx = vec!["vta".to_string(), "mediator".to_string()];
        assert_eq!(format_contexts(&ctx), "vta, mediator");
    }

    // ── format_role ────────────────────────────────────────────────

    #[test]
    fn test_format_role_admin_no_contexts_is_super_admin() {
        assert_eq!(format_role("admin", &[]), "super admin");
    }

    #[test]
    fn test_format_role_admin_with_contexts_stays_admin() {
        let ctx = vec!["vta".to_string()];
        assert_eq!(format_role("admin", &ctx), "admin");
    }

    #[test]
    fn test_format_role_initiator_unchanged() {
        assert_eq!(format_role("initiator", &[]), "initiator");
    }

    #[test]
    fn test_format_role_application_unchanged() {
        let ctx = vec!["app".to_string()];
        assert_eq!(format_role("application", &ctx), "application");
    }

    // ── validate_role ──────────────────────────────────────────────

    #[test]
    fn test_validate_role_admin_ok() {
        assert!(validate_role("admin").is_ok());
    }

    #[test]
    fn test_validate_role_initiator_ok() {
        assert!(validate_role("initiator").is_ok());
    }

    #[test]
    fn test_validate_role_application_ok() {
        assert!(validate_role("application").is_ok());
    }

    #[test]
    fn test_validate_role_unknown_fails() {
        let err = validate_role("superuser").unwrap_err();
        assert!(err.to_string().contains("invalid role 'superuser'"));
    }

    #[test]
    fn test_validate_role_empty_fails() {
        assert!(validate_role("").is_err());
    }

    // ── requires_auth ──────────────────────────────────────────────

    #[test]
    fn test_requires_auth_health_false() {
        assert!(!requires_auth(&Commands::Health));
    }

    #[test]
    fn test_requires_auth_auth_login_false() {
        let cmd = Commands::Auth {
            command: AuthCommands::Login {
                credential: "test".into(),
            },
        };
        assert!(!requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_keys_true() {
        let cmd = Commands::Keys {
            command: KeyCommands::List {
                limit: 50,
                offset: 0,
                status: None,
            },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_config_true() {
        let cmd = Commands::Config {
            command: ConfigCommands::Get,
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_acl_true() {
        let cmd = Commands::Acl {
            command: AclCommands::List { context: None },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_contexts_true() {
        let cmd = Commands::Contexts {
            command: ContextCommands::List,
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_setup_false() {
        assert!(!requires_auth(&Commands::Setup));
    }

    #[test]
    fn test_requires_auth_community_false() {
        let cmd = Commands::Community {
            command: CommunityCommands::List,
        };
        assert!(!requires_auth(&cmd));
    }
}
