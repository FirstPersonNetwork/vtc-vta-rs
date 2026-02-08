mod auth;
mod client;

use clap::{Parser, Subcommand};
use client::{
    CreateContextRequest, CreateKeyRequest, UpdateConfigRequest, UpdateContextRequest, VtaClient,
};
use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
    TerminalOptions, Viewport,
};
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

    /// Application context management
    Contexts {
        #[command(subcommand)]
        command: ContextCommands,
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
        /// Application context ID
        #[arg(long)]
        context_id: Option<String>,
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
        },
        Commands::Keys { command } => match command {
            KeyCommands::Create {
                key_type,
                derivation_path,
                mnemonic,
                label,
                context_id,
            } => {
                cmd_key_create(&client, &key_type, &derivation_path, mnemonic, label, context_id)
                    .await
            }
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
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        other => return Err(format!("unknown key type '{other}', expected ed25519 or x25519").into()),
    };
    let req = CreateKeyRequest {
        key_type,
        derivation_path: derivation_path.to_string(),
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

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["Label", "Type", "Status", "Path", "ID", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .keys
        .iter()
        .map(|key| {
            let label = key.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = key.created_at.format("%Y-%m-%d").to_string();

            let status_cell = match key.status {
                vtc_vta_sdk::keys::KeyStatus::Active => {
                    Cell::from(key.status.to_string()).style(Style::default().fg(Color::Green))
                }
                vtc_vta_sdk::keys::KeyStatus::Revoked => {
                    Cell::from(key.status.to_string()).style(Style::default().fg(Color::Red))
                }
            };

            Row::new(vec![
                Cell::from(label),
                Cell::from(key.key_type.to_string()),
                status_cell,
                Cell::from(key.derivation_path.clone()),
                Cell::from(key.key_id.clone())
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(created),
            ])
        })
        .collect();

    let title = format!(" Keys ({}\u{2013}{} of {}) ", offset + 1, end, resp.total);

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),      // Label
            Constraint::Length(9),     // Type
            Constraint::Length(9),     // Status
            Constraint::Length(16),    // Path
            Constraint::Length(36),    // ID
            Constraint::Length(10),    // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    // +4 = top border + header + header bottom_margin + bottom border
    let height = resp.keys.len() as u16 + 4;
    let mut terminal = ratatui::init_with_options(TerminalOptions {
        viewport: Viewport::Inline(height),
    });
    terminal.draw(|frame| frame.render_widget(table, frame.area()))?;
    ratatui::restore();
    println!();

    Ok(())
}

// ── Context commands ────────────────────────────────────────────────

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
            Constraint::Length(16),    // ID
            Constraint::Min(20),       // Name
            Constraint::Length(30),     // DID
            Constraint::Length(16),     // Base Path
            Constraint::Length(10),     // Created
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
    let mut terminal = ratatui::init_with_options(TerminalOptions {
        viewport: Viewport::Inline(height),
    });
    terminal.draw(|frame| frame.render_widget(table, frame.area()))?;
    ratatui::restore();
    println!();

    Ok(())
}

async fn cmd_context_get(
    client: &VtaClient,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
