/// Derivation path for the VTA's Ed25519 signing/verification key.
pub const VTA_SIGNING_KEY_PATH: &str = "m/44'/0'/0'";

/// Derivation path for the VTA's X25519 key-agreement key.
pub const VTA_KEY_AGREEMENT_PATH: &str = "m/44'/0'/1'";

/// Base derivation path for VTA pre-rotation keys (`m/44'/1'/N'`).
pub const VTA_PRE_ROTATION_BASE: &str = "m/44'/1'";

/// Base derivation path for mediator pre-rotation keys (`m/44'/2'/N'`).
pub const MEDIATOR_PRE_ROTATION_BASE: &str = "m/44'/2'";

/// Base derivation path for admin pre-rotation keys (`m/44'/3'/N'`).
pub const ADMIN_PRE_ROTATION_BASE: &str = "m/44'/3'";

/// BIP-32 derivation path for the JWT signing key (dedicated, not the DID signing key).
pub const JWT_KEY_PATH: &str = "m/44'/3'/0'";

/// Derivation path for the mediator's Ed25519 signing/verification key.
pub const MEDIATOR_SIGNING_KEY_PATH: &str = "m/44'/4'/0'";

/// Derivation path for the mediator's X25519 key-agreement key.
pub const MEDIATOR_KEY_AGREEMENT_PATH: &str = "m/44'/4'/1'";

/// Derivation path for the admin did:webvh Ed25519 signing/verification key.
pub const ADMIN_SIGNING_KEY_PATH: &str = "m/44'/5'/0'";

/// Derivation path for the admin did:webvh X25519 key-agreement key.
pub const ADMIN_KEY_AGREEMENT_PATH: &str = "m/44'/5'/1'";

/// Derivation path for the admin did:key Ed25519 key.
pub const ADMIN_DID_KEY_PATH: &str = "m/44'/5'/2'";
