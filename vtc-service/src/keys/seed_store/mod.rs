#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "config-secret")]
mod config;
#[cfg(feature = "keyring")]
mod keyring;
#[cfg(feature = "gcp-secrets")]
mod gcp;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSecretStore;
#[cfg(feature = "config-secret")]
pub use config::ConfigSecretStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSecretStore;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSecretStore;

use std::future::Future;
use std::pin::Pin;

use crate::config::AppConfig;
use crate::error::AppError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Store for VTC key material (64 bytes: 32 Ed25519 + 32 X25519).
pub trait SecretStore: Send + Sync {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>>;
    fn set(&self, secret: &[u8]) -> BoxFuture<'_, Result<(), AppError>>;
    /// Remove the secret from the backend. Default is a no-op (backends where
    /// `set` overwrites in-place don't need explicit deletion).
    fn delete(&self) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Create a secret store backend based on compiled features and configuration.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. Config file secret (if `config-secret` compiled + `secrets.secret` set)
/// 4. OS keyring (if `keyring` compiled — the default)
#[allow(unused_variables)]
pub fn create_secret_store(config: &AppConfig) -> Result<Box<dyn SecretStore>, AppError> {
    #[cfg(feature = "aws-secrets")]
    if config.secrets.aws_secret_name.is_some() {
        let store = AwsSecretStore::new(
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
        let store = GcpSecretStore::new(project, config.secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "config-secret")]
    if config.secrets.secret.is_some() {
        let store = ConfigSecretStore::new(config.secrets.secret.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "keyring")]
    {
        let store = KeyringSecretStore::new(&config.secrets.keyring_service, "vtc_secret");
        return Ok(Box::new(store));
    }

    #[allow(unreachable_code)]
    Err(AppError::Config(
        "no secret store backend available — compile with at least one of: keyring, config-secret, aws-secrets, gcp-secrets".into(),
    ))
}
