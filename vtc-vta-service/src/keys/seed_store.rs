use std::future::Future;
use std::pin::Pin;

use crate::error::AppError;

type GetFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + 'a>>;
type SetFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>>;

pub trait SeedStore: Send + Sync {
    fn get(&self) -> GetFuture<'_>;
    fn set(&self, seed: &[u8]) -> SetFuture<'_>;
}

pub struct KeyringSeedStore {
    service: String,
    user: String,
}

impl KeyringSeedStore {
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }
}

impl SeedStore for KeyringSeedStore {
    fn get(&self) -> GetFuture<'_> {
        let service = self.service.clone();
        let user = self.user.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
                    AppError::Keyring(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.get_password() {
                    Ok(hex_seed) => {
                        let bytes = hex::decode(&hex_seed).map_err(|e| {
                            AppError::Keyring(format!("failed to decode seed: {e}"))
                        })?;
                        Ok(Some(bytes))
                    }
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(AppError::Keyring(format!("failed to read seed: {e}"))),
                }
            })
            .await
            .unwrap()
        })
    }

    fn set(&self, seed: &[u8]) -> SetFuture<'_> {
        let service = self.service.clone();
        let user = self.user.clone();
        let hex_seed = hex::encode(seed);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
                    AppError::Keyring(format!("failed to create keyring entry: {e}"))
                })?;
                entry
                    .set_password(&hex_seed)
                    .map_err(|e| AppError::Keyring(format!("failed to store seed: {e}")))
            })
            .await
            .unwrap()
        })
    }
}
