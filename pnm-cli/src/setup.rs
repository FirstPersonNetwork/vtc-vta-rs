use crate::auth;
use crate::config::{PnmConfig, save_config};

/// Non-interactive setup: configure URL and optionally authenticate.
pub async fn run_setup(
    url: &str,
    credential: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = url.trim_end_matches('/').to_string();

    let config = PnmConfig {
        url: Some(url.clone()),
    };
    save_config(&config)?;

    let path = crate::config::config_path()?;
    println!("Config saved to: {}", path.display());
    println!("  URL: {url}");

    if let Some(cred) = credential {
        println!();
        auth::login(cred, &url).await?;
    }

    Ok(())
}
