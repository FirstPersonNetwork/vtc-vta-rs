use crate::error::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT claims for VTA access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub sub: String,
    pub session_id: String,
    pub role: String,
    pub exp: u64,
}

/// Holds the JWT encoding and decoding keys derived from an Ed25519 seed.
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKeys {
    /// Create JWT keys from raw 32-byte Ed25519 private key bytes.
    ///
    /// Computes the public key and wraps both in DER format as required
    /// by `jsonwebtoken`'s `from_ed_der()` methods.
    pub fn from_ed25519_bytes(private_bytes: &[u8; 32]) -> Result<Self, AppError> {
        // Compute the Ed25519 public key from the private key seed
        let signing_key = ed25519_dalek::SigningKey::from_bytes(private_bytes);
        let public_bytes = signing_key.verifying_key().to_bytes();

        // Build PKCS8 v2 DER for the private key (used by EncodingKey)
        //
        // SEQUENCE {
        //   INTEGER 0               (version v1)
        //   SEQUENCE { OID 1.3.101.112 }   (Ed25519)
        //   OCTET STRING { OCTET STRING <32 private bytes> }
        //   [1] { BIT STRING { 0x00 <32 public bytes> } }
        // }
        let mut pkcs8 = Vec::with_capacity(96);
        pkcs8.extend_from_slice(&[
            0x30, 0x52, // SEQUENCE, 82 bytes
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier
            0x04, 0x22, 0x04, 0x20, // OCTET STRING { OCTET STRING, 32 bytes }
        ]);
        pkcs8.extend_from_slice(private_bytes);
        pkcs8.extend_from_slice(&[
            0xa1, 0x23, // [1] EXPLICIT, 35 bytes
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
        ]);
        pkcs8.extend_from_slice(&public_bytes);

        // Build SubjectPublicKeyInfo (SPKI) DER for the public key (used by DecodingKey)
        //
        // SEQUENCE {
        //   SEQUENCE { OID 1.3.101.112 }
        //   BIT STRING { 0x00 <32 public bytes> }
        // }
        let mut spki = Vec::with_capacity(44);
        spki.extend_from_slice(&[
            0x30, 0x2a, // SEQUENCE, 42 bytes
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
        ]);
        spki.extend_from_slice(&public_bytes);

        let encoding = EncodingKey::from_ed_der(&pkcs8);
        let decoding = DecodingKey::from_ed_der(&spki);

        Ok(Self { encoding, decoding })
    }

    /// Encode claims into a signed JWT access token.
    pub fn encode(&self, claims: &Claims) -> Result<String, AppError> {
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| AppError::Internal(format!("JWT encode failed: {e}")))
    }

    /// Decode and validate a JWT access token, returning the claims.
    pub fn decode(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["VTA"]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id", "role"]);

        jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| AppError::Unauthorized(format!("invalid token: {e}")))
    }

    /// Create claims for a new access token.
    pub fn new_claims(sub: String, session_id: String, role: String, expiry_secs: u64) -> Claims {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + expiry_secs;

        Claims {
            aud: "VTA".to_string(),
            sub,
            session_id,
            role,
            exp,
        }
    }
}
