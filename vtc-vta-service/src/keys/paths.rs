use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// VTA entity keys: signing, key-agreement, pre-rotation, etc.
pub const VTA_KEY_BASE: &str = "m/26'/0'";

/// Admin keys: signing, key-agreement, did:key, etc.
pub const ADMIN_KEY_BASE: &str = "m/26'/1'";

/// External applications (reserved base).
pub const EXTERNAL_APP_BASE: &str = "m/26'/2'";

/// DIDComm Messaging Mediator keys.
pub const MEDIATOR_KEY_BASE: &str = "m/26'/2'/1'";

/// Trust Registry keys (placeholder).
pub const TRUST_REGISTRY_KEY_BASE: &str = "m/26'/2'/2'";

/// Construct a full derivation path from a base and index.
pub fn path_at(base: &str, index: u32) -> String {
    format!("{base}/{index}'")
}

/// Allocate the next sequential derivation path from a group's counter.
///
/// Reads the current counter for `base` from the keys keyspace,
/// constructs `{base}/{N}'`, increments the counter, and returns the path.
pub async fn allocate_path(
    keys_ks: &KeyspaceHandle,
    base: &str,
) -> Result<String, AppError> {
    let counter_key = format!("path_counter:{base}");
    let current: u32 = match keys_ks.get_raw(counter_key.as_str()).await? {
        Some(bytes) => {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| AppError::Internal("corrupt path counter".into()))?;
            u32::from_le_bytes(arr)
        }
        None => 0,
    };
    let path = path_at(base, current);
    keys_ks
        .insert_raw(counter_key, (current + 1).to_le_bytes().to_vec())
        .await?;
    Ok(path)
}
