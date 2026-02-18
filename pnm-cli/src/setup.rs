use std::io::{self, BufRead, Write};

use vta_sdk::credentials::CredentialBundle;

use crate::auth;
use crate::config::{PnmConfig, save_config};

/// Configure PNM with a VTA credential. The URL is extracted from the credential bundle.
/// If no credential is provided on the CLI, the user is prompted to paste one interactively.
pub async fn run_setup(
    credential: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential = match credential {
        Some(cred) => cred.to_string(),
        None => {
            eprint!("Paste your VTA admin credential: ");
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                return Err("No credential provided.".into());
            }
            trimmed
        }
    };

    // Decode credential to extract VTA URL
    let bundle = CredentialBundle::decode(&credential)?;
    let url = bundle
        .vta_url
        .ok_or("Credential bundle does not contain a VTA URL. Please ensure the credential was generated with a VTA URL.")?;
    let url = url.trim_end_matches('/').to_string();

    let config = PnmConfig {
        url: Some(url.clone()),
    };
    save_config(&config)?;

    let path = crate::config::config_path()?;
    println!("Config saved to: {}", path.display());
    println!("  URL: {url}");
    println!();

    auth::login(&credential, &url).await?;

    Ok(())
}
