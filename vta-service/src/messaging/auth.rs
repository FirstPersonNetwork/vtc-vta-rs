use affinidi_tdk::didcomm::Message;

use crate::acl::{AclEntry, Role, get_acl_entry};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// DIDComm authorization info extracted from a message sender DID.
///
/// Mirrors the REST `AuthClaims` extractor but works from the DIDComm
/// message `from` field rather than a JWT token.
pub struct DidcommAuth {
    pub did: String,
    pub role: Role,
    pub allowed_contexts: Vec<String>,
}

impl DidcommAuth {
    /// Extract sender DID from a DIDComm message and look up their ACL entry.
    pub async fn from_message(msg: &Message, acl_ks: &KeyspaceHandle) -> Result<Self, AppError> {
        let did = msg
            .from
            .as_deref()
            .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;

        // Strip any fragment (e.g. did:key:z6Mk...#z6Mk... → did:key:z6Mk...)
        let base_did = did.split('#').next().unwrap_or(did);

        let entry: AclEntry = get_acl_entry(acl_ks, base_did)
            .await?
            .ok_or_else(|| AppError::Forbidden(format!("DID not in ACL: {base_did}")))?;

        Ok(DidcommAuth {
            did: base_did.to_string(),
            role: entry.role,
            allowed_contexts: entry.allowed_contexts,
        })
    }

    pub fn is_super_admin(&self) -> bool {
        self.role == Role::Admin && self.allowed_contexts.is_empty()
    }

    pub fn has_context_access(&self, context_id: &str) -> bool {
        self.is_super_admin() || self.allowed_contexts.contains(&context_id.to_string())
    }

    pub fn require_context(&self, context_id: &str) -> Result<(), AppError> {
        if self.has_context_access(context_id) {
            return Ok(());
        }
        Err(AppError::Forbidden(format!(
            "no access to context: {context_id}"
        )))
    }

    pub fn default_context(&self) -> Option<&str> {
        if self.allowed_contexts.len() == 1 {
            Some(&self.allowed_contexts[0])
        } else {
            None
        }
    }

    pub fn require_admin(&self) -> Result<(), AppError> {
        if self.role == Role::Admin {
            return Ok(());
        }
        Err(AppError::Forbidden("admin role required".into()))
    }

    pub fn require_manage(&self) -> Result<(), AppError> {
        if self.role == Role::Admin || self.role == Role::Initiator {
            return Ok(());
        }
        Err(AppError::Forbidden(
            "admin or initiator role required".into(),
        ))
    }

    pub fn require_super_admin(&self) -> Result<(), AppError> {
        if self.is_super_admin() {
            return Ok(());
        }
        Err(AppError::Forbidden("super admin required".into()))
    }
}
