mod acl;
mod auth;
mod config;
mod contexts;
mod error;
mod keys;
mod routes;
mod server;
#[cfg(feature = "setup")]
mod setup;
mod store;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use config::{AppConfig, LogFormat};
use keys::seed_store::KeyringSeedStore;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "vtc-vta", about = "Verified Trust Agent", version)]
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
        None => {
            let config = match AppConfig::load(cli.config) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error: {e}");
                    eprintln!();
                    eprintln!("To set up a new VTA instance, run:");
                    eprintln!("  vtc-vta setup");
                    eprintln!();
                    eprintln!("Or specify a config file:");
                    eprintln!("  vtc-vta --config <path>");
                    std::process::exit(1);
                }
            };

            init_tracing(&config);

            let store = store::Store::open(&config.store).expect("failed to open store");
            let seed_store = Arc::new(KeyringSeedStore::new("vtc-vta", "master_seed"));

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
