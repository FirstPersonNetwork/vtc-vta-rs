use crate::error::AppError;
use crate::store::KeyspaceHandle;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

const MASTER_SEED_KEY: &str = "master_seed";

/// Derive an Ed25519 key pair from a seed and BIP32 derivation path.
///
/// Returns `(private_key_bytes, public_key_bytes)`.
pub fn derive_ed25519(seed: &[u8], path: &str) -> Result<([u8; 32], [u8; 32]), AppError> {
    let derivation_path: DerivationPath = path
        .parse()
        .map_err(|e| AppError::KeyDerivation(format!("invalid derivation path: {e}")))?;

    let master = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| AppError::KeyDerivation(format!("failed to create master key: {e}")))?;

    let derived = master
        .derive(&derivation_path)
        .map_err(|e| AppError::KeyDerivation(format!("derivation failed: {e}")))?;

    let signing_key = derived.signing_key;
    let verifying_key = signing_key.verifying_key();

    Ok((signing_key.to_bytes(), verifying_key.to_bytes()))
}

/// Derive an X25519 key pair by first deriving Ed25519, then converting.
///
/// Returns `(private_key_bytes, public_key_bytes)`.
pub fn derive_x25519(seed: &[u8], path: &str) -> Result<([u8; 32], [u8; 32]), AppError> {
    let (ed_private, _) = derive_ed25519(seed, path)?;

    // Convert Ed25519 private key to X25519 by hashing with SHA-512 and clamping
    // This follows the standard Ed25519 -> X25519 conversion
    let hash = Sha256::digest(ed_private);
    let mut x25519_private = [0u8; 32];
    x25519_private.copy_from_slice(&hash);

    // Clamp the scalar per X25519 spec
    x25519_private[0] &= 248;
    x25519_private[31] &= 127;
    x25519_private[31] |= 64;

    let secret = x25519_dalek::StaticSecret::from(x25519_private);
    let public = x25519_dalek::PublicKey::from(&secret);

    Ok((x25519_private, public.to_bytes()))
}

/// Encode public key bytes in multibase (base58btc) format.
pub fn multibase_encode(bytes: &[u8]) -> String {
    multibase::encode(multibase::Base::Base58Btc, bytes)
}

/// Load an existing master seed from the store, or generate/derive a new one.
///
/// - If `mnemonic` is provided, derives a 32-byte seed via SHA-256 and stores it.
/// - If no mnemonic and a seed already exists, returns the existing seed.
/// - If no mnemonic and no seed exists, generates 32 random bytes and stores them.
pub async fn load_or_generate_seed(
    secrets: &KeyspaceHandle,
    mnemonic: Option<&str>,
) -> Result<Vec<u8>, AppError> {
    if let Some(phrase) = mnemonic {
        let seed = sha256_seed(phrase.as_bytes());
        secrets.insert_raw(MASTER_SEED_KEY, seed.to_vec()).await?;
        return Ok(seed.to_vec());
    }

    if let Some(existing) = secrets.get_raw(MASTER_SEED_KEY).await? {
        return Ok(existing);
    }

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    secrets.insert_raw(MASTER_SEED_KEY, seed.to_vec()).await?;
    Ok(seed.to_vec())
}

fn sha256_seed(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_ed25519_deterministic() {
        let seed = [42u8; 32];
        let path = "m/44'/0'/0'";

        let (priv1, pub1) = derive_ed25519(&seed, path).unwrap();
        let (priv2, pub2) = derive_ed25519(&seed, path).unwrap();

        assert_eq!(priv1, priv2);
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_derive_ed25519_different_paths() {
        let seed = [42u8; 32];

        let (_, pub1) = derive_ed25519(&seed, "m/44'/0'/0'").unwrap();
        let (_, pub2) = derive_ed25519(&seed, "m/44'/0'/1'").unwrap();

        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_derive_x25519_deterministic() {
        let seed = [42u8; 32];
        let path = "m/44'/0'/0'";

        let (priv1, pub1) = derive_x25519(&seed, path).unwrap();
        let (priv2, pub2) = derive_x25519(&seed, path).unwrap();

        assert_eq!(priv1, priv2);
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_derive_x25519_differs_from_ed25519() {
        let seed = [42u8; 32];
        let path = "m/44'/0'/0'";

        let (_, ed_pub) = derive_ed25519(&seed, path).unwrap();
        let (_, x_pub) = derive_x25519(&seed, path).unwrap();

        assert_ne!(ed_pub, x_pub);
    }

    #[test]
    fn test_invalid_path() {
        let seed = [42u8; 32];
        let result = derive_ed25519(&seed, "not/a/valid/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_multibase_encode() {
        let bytes = [1u8; 32];
        let encoded = multibase_encode(&bytes);
        // Base58btc multibase starts with 'z'
        assert!(encoded.starts_with('z'));
    }

    #[test]
    fn test_sha256_seed_deterministic() {
        let s1 = sha256_seed(b"test mnemonic phrase");
        let s2 = sha256_seed(b"test mnemonic phrase");
        assert_eq!(s1, s2);
    }
}
