use crate::config::StoreConfig;
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

#[derive(Clone)]
pub struct Store {
    db: fjall::Database,
}

#[derive(Clone)]
pub struct KeyspaceHandle {
    keyspace: fjall::Keyspace,
}

impl Store {
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;

        info!(path = %config.data_dir.display(), "opening store");

        let db = fjall::Database::builder(&config.data_dir).open()?;

        Ok(Self { db })
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let keyspace = self.db.keyspace(name, KeyspaceCreateOptions::default)?;
        Ok(KeyspaceHandle { keyspace })
    }

    pub async fn persist(&self) -> Result<(), AppError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.persist(PersistMode::SyncAll))
            .await
            .unwrap()?;
        Ok(())
    }
}

impl KeyspaceHandle {
    pub async fn insert<V: Serialize + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>> + Send + 'static,
        value: &V,
    ) -> Result<(), AppError> {
        let bytes = serde_json::to_vec(value)?;
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.insert(key.into(), bytes))
            .await
            .unwrap()?;
        Ok(())
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>> + Send + 'static,
    ) -> Result<Option<V>, AppError> {
        let ks = self.keyspace.clone();
        let result = tokio::task::spawn_blocking(move || ks.get(key.into()))
            .await
            .unwrap()?;

        match result {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>> + Send + 'static) -> Result<(), AppError> {
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.remove(key.into()))
            .await
            .unwrap()?;
        Ok(())
    }

    pub async fn contains_key(
        &self,
        key: impl Into<Vec<u8>> + Send + 'static,
    ) -> Result<bool, AppError> {
        let ks = self.keyspace.clone();
        let result = tokio::task::spawn_blocking(move || ks.contains_key(key.into()))
            .await
            .unwrap()?;
        Ok(result)
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>> + Send + 'static,
        value: impl Into<Vec<u8>> + Send + 'static,
    ) -> Result<(), AppError> {
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.insert(key.into(), value.into()))
            .await
            .unwrap()?;
        Ok(())
    }

    pub async fn get_raw(
        &self,
        key: impl Into<Vec<u8>> + Send + 'static,
    ) -> Result<Option<Vec<u8>>, AppError> {
        let ks = self.keyspace.clone();
        let result = tokio::task::spawn_blocking(move || ks.get(key.into()))
            .await
            .unwrap()?;
        Ok(result.map(|v| v.to_vec()))
    }
}
