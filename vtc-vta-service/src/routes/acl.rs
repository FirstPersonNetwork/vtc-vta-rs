use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::acl::{
    AclEntry, Role, check_acl, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::auth::ManageAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;

// ---------- GET /acl ----------

#[derive(Debug, Serialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    pub created_at: u64,
    pub created_by: String,
}

impl From<AclEntry> for AclEntryResponse {
    fn from(e: AclEntry) -> Self {
        AclEntryResponse {
            did: e.did,
            role: e.role,
            label: e.label,
            created_at: e.created_at,
            created_by: e.created_by,
        }
    }
}

pub async fn list_acl(
    _auth: ManageAuth,
    State(state): State<AppState>,
) -> Result<Json<AclListResponse>, AppError> {
    let acl = state.store.keyspace("acl")?;
    let entries = list_acl_entries(&acl).await?;
    Ok(Json(AclListResponse {
        entries: entries.into_iter().map(AclEntryResponse::from).collect(),
    }))
}

// ---------- POST /acl ----------

#[derive(Debug, Deserialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
}

pub async fn create_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<AclEntryResponse>), AppError> {
    let acl = state.store.keyspace("acl")?;

    // Check if entry already exists
    if get_acl_entry(&acl, &req.did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {}",
            req.did
        )));
    }

    let entry = AclEntry {
        did: req.did,
        role: req.role,
        label: req.label,
        created_at: now_epoch(),
        created_by: auth.0.did,
    };

    store_acl_entry(&acl, &entry).await?;

    Ok((StatusCode::CREATED, Json(AclEntryResponse::from(entry))))
}

// ---------- GET /acl/{did} ----------

pub async fn get_acl(
    _auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let acl = state.store.keyspace("acl")?;
    let entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- PATCH /acl/{did} ----------

#[derive(Debug, Deserialize)]
pub struct UpdateAclRequest {
    pub role: Option<Role>,
    pub label: Option<String>,
}

pub async fn update_acl(
    _auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let acl = state.store.keyspace("acl")?;
    let mut entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    if let Some(role) = req.role {
        entry.role = role;
    }
    if let Some(label) = req.label {
        entry.label = Some(label);
    }

    store_acl_entry(&acl, &entry).await?;

    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- DELETE /acl/{did} ----------

pub async fn delete_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    // Prevent self-deletion
    if auth.0.did == did {
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    let acl = state.store.keyspace("acl")?;

    // Verify entry exists
    check_acl(&acl, &did).await.map_err(|_| {
        AppError::NotFound(format!("ACL entry not found for DID: {did}"))
    })?;

    delete_acl_entry(&acl, &did).await?;

    Ok(StatusCode::NO_CONTENT)
}
