pub mod derivation;
pub mod paths;
pub mod seed_store;

pub use vta_sdk::keys::{KeyRecord, KeyStatus, KeyType};

pub fn store_key(key_id: &str) -> String {
    format!("key:{key_id}")
}

/// Encode an Ed25519 public key as a multibase Base58BTC string with multicodec prefix.
pub fn ed25519_multibase_pubkey(public_key_bytes: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0xed, 0x01]);
    buf.extend_from_slice(public_key_bytes);
    multibase::encode(multibase::Base::Base58Btc, &buf)
}
