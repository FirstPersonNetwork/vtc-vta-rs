pub mod derivation;
pub mod seed_store;

pub use vtc_vta_sdk::keys::{KeyRecord, KeyStatus, KeyType};

pub fn store_key(key_id: &str) -> String {
    format!("key:{key_id}")
}
