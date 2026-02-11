#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "config-seed")]
mod config;
#[cfg(feature = "keyring")]
mod keyring;
#[cfg(feature = "gcp-secrets")]
mod gcp;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSeedStore;
#[cfg(feature = "config-seed")]
pub use config::ConfigSeedStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSeedStore;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSeedStore;

use std::future::Future;
use std::pin::Pin;

use crate::config::AppConfig;
use crate::error::AppError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait SeedStore: Send + Sync {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>>;
    fn set(&self, seed: &[u8]) -> BoxFuture<'_, Result<(), AppError>>;
}

/// Create a seed store backend based on compiled features and configuration.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. Config file seed (if `config-seed` compiled + `secrets.seed` set)
/// 4. OS keyring (if `keyring` compiled — the default)
#[allow(unused_variables)]
pub fn create_seed_store(config: &AppConfig) -> Result<Box<dyn SeedStore>, AppError> {
    #[cfg(feature = "aws-secrets")]
    if config.secrets.aws_secret_name.is_some() {
        let store = AwsSeedStore::new(
            config.secrets.aws_secret_name.clone().unwrap(),
            config.secrets.aws_region.clone(),
        );
        return Ok(Box::new(store));
    }

    #[cfg(feature = "gcp-secrets")]
    if config.secrets.gcp_secret_name.is_some() {
        let project = config.secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSeedStore::new(project, config.secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "config-seed")]
    if config.secrets.seed.is_some() {
        let store = ConfigSeedStore::new(config.secrets.seed.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "keyring")]
    {
        let store = KeyringSeedStore::new("vta", "master_seed");
        return Ok(Box::new(store));
    }

    #[allow(unreachable_code)]
    Err(AppError::Config(
        "no seed store backend available — compile with at least one of: keyring, config-seed, aws-secrets, gcp-secrets".into(),
    ))
}
