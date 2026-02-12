use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use dialoguer::{Input, Select};

use crate::auth;
use crate::client::{CreateContextRequest, GenerateCredentialsRequest, VtaClient};
use crate::config::{
    CommunityConfig, PersonalVtaConfig, community_keyring_key, load_config, save_config,
    PERSONAL_KEYRING_KEY,
};

/// Derive a URL-safe slug from a community name.
///
/// Lowercases, replaces whitespace/non-alphanumeric with hyphens, trims hyphens.
fn slugify(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    slug.trim_matches('-')
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Try to resolve a VTA URL from a DID's `#vta` service endpoint.
async fn resolve_vta_url(did: &str) -> Option<String> {
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok()?;

    let resolved = resolver.resolve(did).await.ok()?;
    let svc = resolved.doc.find_service("vta")?;
    let url = svc.service_endpoint.get_uri()?;

    Some(url.trim_end_matches('/').to_string())
}

/// Prompt for a VTA DID, resolve the `#vta` service URL if possible,
/// then ask for the URL (pre-filled with the discovered value or manual entry).
///
/// `label` is a human-readable prefix like "Personal" or "Community".
async fn prompt_vta_url(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    let did: String = Input::new()
        .with_prompt(format!("{label} VTA DID (press Enter to skip)"))
        .allow_empty(true)
        .interact_text()?;

    let discovered_url = if did.is_empty() {
        None
    } else {
        eprintln!("Resolving DID...");
        match resolve_vta_url(&did).await {
            Some(url) => {
                eprintln!("  Discovered VTA URL: {url}");
                Some(url)
            }
            None => {
                eprintln!("  No #vta service endpoint found in DID document.");
                None
            }
        }
    };

    let vta_url: String = if let Some(url) = discovered_url {
        Input::new()
            .with_prompt(format!("{label} VTA URL"))
            .default(url)
            .interact_text()?
    } else {
        Input::new()
            .with_prompt(format!("{label} VTA URL"))
            .interact_text()?
    };

    Ok(vta_url)
}

/// Run the interactive setup wizard.
pub async fn run_setup_wizard() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the CNM setup wizard.\n");

    let mut config = load_config()?;

    // ── Personal VTA ────────────────────────────────────────────────
    let personal_url = prompt_vta_url("Personal").await?;

    let personal_credential: String = Input::new()
        .with_prompt("Personal VTA credential (base64)")
        .interact_text()?;

    // Authenticate against personal VTA
    eprintln!();
    auth::login(&personal_credential, &personal_url, Some(PERSONAL_KEYRING_KEY)).await?;

    config.personal_vta = Some(PersonalVtaConfig {
        url: personal_url.clone(),
    });

    // ── Community ───────────────────────────────────────────────────
    let community_name: String = Input::new()
        .with_prompt("Community name")
        .interact_text()?;

    let default_slug = slugify(&community_name);
    let community_slug: String = Input::new()
        .with_prompt("Community slug (short identifier)")
        .default(default_slug)
        .interact_text()?;

    let community_url = prompt_vta_url("Community").await?;

    let join_options = &[
        "Import existing credential",
        "Generate from personal VTA",
    ];
    let join_choice = Select::new()
        .with_prompt("How do you want to join this community?")
        .items(join_options)
        .default(0)
        .interact()?;

    let context_id = match join_choice {
        // Import existing credential
        0 => {
            let credential: String = Input::new()
                .with_prompt("Community credential (base64)")
                .interact_text()?;

            let keyring_key = community_keyring_key(&community_slug);
            eprintln!();
            auth::login(&credential, &community_url, Some(&keyring_key)).await?;

            None
        }
        // Generate from personal VTA
        _ => {
            let context_slug = format!("cnm-{community_slug}");
            let context_name = format!("CNM - {community_name}");

            // Authenticate personal VTA client
            let mut personal_client = VtaClient::new(&personal_url);
            let token =
                auth::ensure_authenticated(&personal_url, Some(PERSONAL_KEYRING_KEY)).await?;
            personal_client.set_token(token);

            // Create context in personal VTA
            eprintln!("\nCreating context '{context_name}' in personal VTA...");
            let ctx_req = CreateContextRequest {
                id: context_slug.clone(),
                name: context_name,
                description: Some(format!(
                    "Community admin identity for {}",
                    community_name
                )),
            };
            match personal_client.create_context(ctx_req).await {
                Ok(ctx) => {
                    eprintln!("  Context created: {} ({})", ctx.id, ctx.base_path);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("409") || msg.to_lowercase().contains("already exists") {
                        eprintln!("  Context '{context_slug}' already exists, reusing it.");
                    } else {
                        return Err(e);
                    }
                }
            }

            // Generate credential in personal VTA
            eprintln!("Generating community admin credential...");
            let cred_req = GenerateCredentialsRequest {
                role: "admin".into(),
                label: Some(format!("CNM community admin — {community_slug}")),
                allowed_contexts: vec![context_slug.clone()],
            };
            let resp = personal_client.generate_credentials(cred_req).await?;

            eprintln!();
            eprintln!("\x1b[1;32mGenerated community admin DID:\x1b[0m {}", resp.did);
            eprintln!();
            eprintln!("To join the community, provide this DID to the community administrator.");
            eprintln!("They will create an ACL entry granting your DID access.");
            eprintln!();
            eprintln!("Once the community admin has granted access, run:");
            eprintln!("  cnm community add");
            eprintln!("and import the credential they provide.");
            eprintln!();

            Some(context_slug)
        }
    };

    // ── Save config ─────────────────────────────────────────────────
    config.communities.insert(
        community_slug.clone(),
        CommunityConfig {
            name: community_name,
            url: community_url,
            context_id,
        },
    );

    // Set as default if first community
    if config.default_community.is_none() || config.communities.len() == 1 {
        config.default_community = Some(community_slug.clone());
    }

    save_config(&config)?;

    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    let path = crate::config::config_path()?;
    eprintln!("  Config saved to: {}", path.display());
    eprintln!("  Default community: {community_slug}");
    eprintln!();

    Ok(())
}

/// Add a new community interactively.
pub async fn add_community() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    let community_name: String = Input::new()
        .with_prompt("Community name")
        .interact_text()?;

    let default_slug = slugify(&community_name);
    let community_slug: String = Input::new()
        .with_prompt("Community slug (short identifier)")
        .default(default_slug)
        .interact_text()?;

    if config.communities.contains_key(&community_slug) {
        return Err(format!(
            "community '{community_slug}' already exists. Use a different slug."
        )
        .into());
    }

    let community_url = prompt_vta_url("Community").await?;

    let credential: String = Input::new()
        .with_prompt("Community credential (base64)")
        .interact_text()?;

    let keyring_key = community_keyring_key(&community_slug);
    eprintln!();
    auth::login(&credential, &community_url, Some(&keyring_key)).await?;

    config.communities.insert(
        community_slug.clone(),
        CommunityConfig {
            name: community_name,
            url: community_url,
            context_id: None,
        },
    );

    if config.default_community.is_none() {
        config.default_community = Some(community_slug.clone());
    }

    save_config(&config)?;

    eprintln!();
    eprintln!("Community '{community_slug}' added.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slugify_basic() {
        assert_eq!(slugify("Storm Network"), "storm-network");
    }

    #[test]
    fn test_slugify_special_chars() {
        assert_eq!(slugify("Acme Corp."), "acme-corp");
    }

    #[test]
    fn test_slugify_multiple_spaces() {
        assert_eq!(slugify("  My   Test  Community  "), "my-test-community");
    }

    #[test]
    fn test_slugify_already_slug() {
        assert_eq!(slugify("already-good"), "already-good");
    }

    #[test]
    fn test_slugify_uppercase() {
        assert_eq!(slugify("UPPERCASE"), "uppercase");
    }

    #[test]
    fn test_slugify_numbers() {
        assert_eq!(slugify("Community 42"), "community-42");
    }
}
