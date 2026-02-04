mod config;
mod error;
mod routes;
mod server;
mod store;

use config::{AppConfig, LogFormat};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let config = AppConfig::load().expect("failed to load configuration");

    init_tracing(&config);

    let store = store::Store::open(&config.store).expect("failed to open store");

    if let Err(e) = server::run(&config, store).await {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
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
