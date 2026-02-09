pub use vta_sdk::contexts::ContextRecord;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn ctx_key(id: &str) -> String {
    format!("ctx:{id}")
}

/// Retrieve a context by ID.
pub async fn get_context(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<ContextRecord>, AppError> {
    ks.get(ctx_key(id)).await
}

/// Store (create or overwrite) a context record.
pub async fn store_context(ks: &KeyspaceHandle, record: &ContextRecord) -> Result<(), AppError> {
    ks.insert(ctx_key(&record.id), record).await
}

/// Delete a context by ID.
pub async fn delete_context(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(ctx_key(id)).await
}

/// List all context records.
pub async fn list_contexts(ks: &KeyspaceHandle) -> Result<Vec<ContextRecord>, AppError> {
    let raw = ks.prefix_iter_raw("ctx:").await?;
    let mut records = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: ContextRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    Ok(records)
}

/// Allocate the next context index and return `(index, base_path)`.
///
/// The counter is stored in the contexts keyspace under `ctx_counter`.
/// Returns the next available index and the corresponding BIP-32 base path
/// `m/26'/2'/N'`.
pub async fn allocate_context_index(
    ks: &KeyspaceHandle,
) -> Result<(u32, String), AppError> {
    let counter_key = "ctx_counter";
    let current: u32 = match ks.get_raw(counter_key).await? {
        Some(bytes) => {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| AppError::Internal("corrupt context counter".into()))?;
            u32::from_le_bytes(arr)
        }
        None => 0,
    };
    let base_path = format!("{CONTEXT_KEY_BASE}/{current}'");
    ks.insert_raw(counter_key, (current + 1).to_le_bytes().to_vec())
        .await?;
    Ok((current, base_path))
}

/// Base path for application context keys.
pub const CONTEXT_KEY_BASE: &str = "m/26'/2'";
