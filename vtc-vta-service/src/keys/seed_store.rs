use crate::error::AppError;

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

    pub async fn get(&self) -> Result<Option<Vec<u8>>, AppError> {
        let service = self.service.clone();
        let user = self.user.clone();
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
        .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
    }

    pub async fn set(&self, seed: &[u8]) -> Result<(), AppError> {
        let service = self.service.clone();
        let user = self.user.clone();
        let hex_seed = hex::encode(seed);
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(&service, &user).map_err(|e| {
                AppError::Keyring(format!("failed to create keyring entry: {e}"))
            })?;
            entry
                .set_password(&hex_seed)
                .map_err(|e| AppError::Keyring(format!("failed to store seed: {e}")))
        })
        .await
        .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
    }
}
