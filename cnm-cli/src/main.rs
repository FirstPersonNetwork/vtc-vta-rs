mod auth;
mod client;

use clap::{Parser, Subcommand};
use client::{CreateKeyRequest, UpdateConfigRequest, VtaClient};
use vtc_vta_sdk::keys::KeyType;

#[derive(Parser)]
#[command(name = "cnm-cli", about = "CLI for VTC Verified Trust Agents")]
struct Cli {
    /// Base URL of the VTA service
    #[arg(long, env = "VTA_URL", default_value = "http://localhost:3000")]
    url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
        vta_did: Option<String>,
        /// Community name
        #[arg(long)]
        community_name: Option<String>,
        /// Community description
        #[arg(long)]
        community_description: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new key
    Create {
        /// Key type: ed25519 or x25519
        #[arg(long)]
        key_type: String,
        /// BIP-32 derivation path (e.g. m/44'/0'/0')
        #[arg(long)]
        derivation_path: String,
        /// BIP-39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
    },
    /// Get a key by ID
    Get {
        /// Key ID
        key_id: String,
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
    !matches!(cmd, Commands::Health | Commands::Auth { .. })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    let mut client = VtaClient::new(&cli.url);

    // Transparent authentication for protected commands
    if requires_auth(&cli.command) {
        match auth::ensure_authenticated(client.base_url()).await {
            Ok(token) => client.set_token(token),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }

    let result = match cli.command {
        Commands::Health => cmd_health(&client).await,
        Commands::Auth { command } => match command {
            AuthCommands::Login { credential } => {
                auth::login(&credential, client.base_url()).await
            }
            AuthCommands::Logout => {
                auth::logout();
                Ok(())
            }
            AuthCommands::Status => {
                auth::status();
                Ok(())
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Get => cmd_config_get(&client).await,
            ConfigCommands::Update {
                vta_did,
                community_name,
                community_description,
            } => {
                cmd_config_update(&client, vta_did, community_name, community_description).await
            }
        },
        Commands::Keys { command } => match command {
            KeyCommands::Create {
                key_type,
                derivation_path,
                mnemonic,
                label,
            } => cmd_key_create(&client, &key_type, &derivation_path, mnemonic, label).await,
            KeyCommands::Get { key_id } => cmd_key_get(&client, &key_id).await,
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

async fn cmd_health(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.health().await?;
    println!("Status:  {}", resp.status);
    println!("Version: {}", resp.version);
    Ok(())
}

async fn cmd_config_get(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get_config().await?;
    println!(
        "VTA DID:               {}",
        resp.vta_did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Community Name:        {}",
        resp.community_name.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Community Description: {}",
        resp.community_description.as_deref().unwrap_or("(not set)")
    );
    Ok(())
}

async fn cmd_config_update(
    client: &VtaClient,
    vta_did: Option<String>,
    community_name: Option<String>,
    community_description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateConfigRequest {
        vta_did,
        community_name,
        community_description,
    };
    let resp = client.update_config(req).await?;
    println!("Configuration updated:");
    println!(
        "  VTA DID:               {}",
        resp.vta_did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Community Name:        {}",
        resp.community_name.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Community Description: {}",
        resp.community_description.as_deref().unwrap_or("(not set)")
    );
    Ok(())
}

async fn cmd_key_create(
    client: &VtaClient,
    key_type: &str,
    derivation_path: &str,
    mnemonic: Option<String>,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        other => return Err(format!("unknown key type '{other}', expected ed25519 or x25519").into()),
    };
    let req = CreateKeyRequest {
        key_type,
        derivation_path: derivation_path.to_string(),
        mnemonic,
        label,
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
) -> Result<(), Box<dyn std::error::Error>> {
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
    let resp = client
        .list_keys(offset, limit, status.as_deref())
        .await?;

    if resp.keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    let end = (offset + resp.keys.len() as u64).min(resp.total);
    println!("Keys (showing {}-{} of {}):", offset + 1, end, resp.total);
    println!(
        "  {:<36}  {:<8}  {:<8}  {:<20}  {}",
        "ID", "Type", "Status", "Label", "Created"
    );
    for key in &resp.keys {
        let label = key.label.as_deref().unwrap_or("\u{2014}");
        let created = key.created_at.format("%Y-%m-%d");
        println!(
            "  {:<36}  {:<8}  {:<8}  {:<20}  {}",
            key.key_id, key.key_type, key.status, label, created
        );
    }
    Ok(())
}
