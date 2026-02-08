use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::contexts::{
    ContextRecord, allocate_context_index, delete_context, get_context, list_contexts,
    store_context,
};
use crate::error::AppError;
use crate::server::AppState;

// ---------- Types ----------

#[derive(Debug, Deserialize)]
pub struct CreateContextRequest {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateContextRequest {
    pub name: Option<String>,
    pub did: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContextResponse {
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    pub base_path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<ContextRecord> for ContextResponse {
    fn from(r: ContextRecord) -> Self {
        ContextResponse {
            id: r.id,
            name: r.name,
            did: r.did,
            description: r.description,
            base_path: r.base_path,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ContextListResponse {
    pub contexts: Vec<ContextResponse>,
}

// ---------- Validation ----------

fn validate_slug(id: &str) -> Result<(), AppError> {
    if id.is_empty() {
        return Err(AppError::Validation("context id cannot be empty".into()));
    }
    if id.len() > 64 {
        return Err(AppError::Validation(
            "context id must be 64 characters or fewer".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AppError::Validation(
            "context id must contain only lowercase alphanumeric characters and hyphens".into(),
        ));
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Err(AppError::Validation(
            "context id must not start or end with a hyphen".into(),
        ));
    }
    Ok(())
}

// ---------- GET /contexts ----------

pub async fn list_contexts_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ContextListResponse>, AppError> {
    let records = list_contexts(&state.contexts_ks).await?;
    let contexts: Vec<ContextResponse> = records
        .into_iter()
        .filter(|r| auth.has_context_access(&r.id))
        .map(ContextResponse::from)
        .collect();
    info!(caller = %auth.did, count = contexts.len(), "contexts listed");
    Ok(Json(ContextListResponse { contexts }))
}

// ---------- POST /contexts ----------

pub async fn create_context_handler(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateContextRequest>,
) -> Result<(StatusCode, Json<ContextResponse>), AppError> {
    validate_slug(&req.id)?;

    // Check for duplicates
    if get_context(&state.contexts_ks, &req.id).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "context already exists: {}",
            req.id
        )));
    }

    let (index, base_path) = allocate_context_index(&state.contexts_ks).await?;

    let now = Utc::now();
    let record = ContextRecord {
        id: req.id.clone(),
        name: req.name,
        did: None,
        description: req.description,
        base_path,
        index,
        created_at: now,
        updated_at: now,
    };

    store_context(&state.contexts_ks, &record).await?;

    info!(id = %record.id, index, "context created");
    Ok((StatusCode::CREATED, Json(ContextResponse::from(record))))
}

// ---------- GET /contexts/{id} ----------

pub async fn get_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ContextResponse>, AppError> {
    auth.require_context(&id)?;
    let record = get_context(&state.contexts_ks, &id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;
    info!(id = %id, "context retrieved");
    Ok(Json(ContextResponse::from(record)))
}

// ---------- PATCH /contexts/{id} ----------

pub async fn update_context_handler(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateContextRequest>,
) -> Result<Json<ContextResponse>, AppError> {
    let mut record = get_context(&state.contexts_ks, &id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    if let Some(name) = req.name {
        record.name = name;
    }
    if let Some(did) = req.did {
        record.did = Some(did);
    }
    if let Some(description) = req.description {
        record.description = Some(description);
    }
    record.updated_at = Utc::now();

    store_context(&state.contexts_ks, &record).await?;

    info!(id = %id, "context updated");
    Ok(Json(ContextResponse::from(record)))
}

// ---------- DELETE /contexts/{id} ----------

pub async fn delete_context_handler(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    // Verify it exists
    get_context(&state.contexts_ks, &id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    delete_context(&state.contexts_ks, &id).await?;

    info!(id = %id, "context deleted");
    Ok(StatusCode::NO_CONTENT)
}
