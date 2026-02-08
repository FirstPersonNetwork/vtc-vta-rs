mod auth;
mod client;

use clap::{Parser, Subcommand};
use client::{
    CreateAclRequest, CreateContextRequest, CreateKeyRequest, GenerateCredentialsRequest,
    UpdateAclRequest, UpdateConfigRequest, UpdateContextRequest, VtaClient,
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
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

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

    let url = cli
        .url
        .or_else(|| auth::stored_url())
        .unwrap_or_else(|| "http://localhost:3000".to_string());
    let mut client = VtaClient::new(&url);

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
                public_url,
            } => {
                cmd_config_update(
                    &client,
                    vta_did,
                    community_name,
                    community_description,
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
                cmd_key_create(&client, &key_type, derivation_path, mnemonic, label, context_id)
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
    println!(
        "Public URL:            {}",
        resp.public_url.as_deref().unwrap_or("(not set)")
    );
    Ok(())
}

async fn cmd_config_update(
    client: &VtaClient,
    vta_did: Option<String>,
    community_name: Option<String>,
    community_description: Option<String>,
    public_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateConfigRequest {
        vta_did,
        community_name,
        community_description,
        public_url,
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
    println!(
        "  Public URL:            {}",
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
        other => return Err(format!("unknown key type '{other}', expected ed25519 or x25519").into()),
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
        _ => Err(format!(
            "invalid role '{role}', expected: admin, initiator, or application"
        )
        .into()),
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
                Cell::from(entry.created_by.clone())
                    .style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" ACL Entries ({}) ", resp.entries.len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(52),    // DID
            Constraint::Length(12),    // Role
            Constraint::Min(16),       // Label
            Constraint::Length(24),    // Contexts
            Constraint::Length(52),    // Created By
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
    let mut terminal = ratatui::init_with_options(TerminalOptions {
        viewport: Viewport::Inline(height),
    });
    terminal.draw(|frame| frame.render_widget(table, frame.area()))?;
    ratatui::restore();
    println!();

    Ok(())
}

async fn cmd_acl_get(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = client.get_acl(did).await?;
    println!("DID:              {}", entry.did);
    println!("Role:             {}", format_role(&entry.role, &entry.allowed_contexts));
    println!(
        "Label:            {}",
        entry.label.as_deref().unwrap_or("(not set)")
    );
    println!("Contexts:         {}", format_contexts(&entry.allowed_contexts));
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
    println!("  Role:     {}", format_role(&entry.role, &entry.allowed_contexts));
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
    println!("  Role:     {}", format_role(&entry.role, &entry.allowed_contexts));
    if let Some(label) = &entry.label {
        println!("  Label:    {label}");
    }
    println!("  Contexts: {}", format_contexts(&entry.allowed_contexts));
    Ok(())
}

async fn cmd_acl_delete(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
