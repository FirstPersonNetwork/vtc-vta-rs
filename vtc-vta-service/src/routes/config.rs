use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::server::AppState;

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub vta_did: Option<String>,
    pub community_name: Option<String>,
    pub community_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigRequest {
    pub vta_did: Option<String>,
    pub community_name: Option<String>,
    pub community_description: Option<String>,
}

pub async fn get_config(State(state): State<AppState>) -> Result<Json<ConfigResponse>, AppError> {
    let config = state.config.read().await;
    Ok(Json(ConfigResponse {
        vta_did: config.vta_did.clone(),
        community_name: config.community_name.clone(),
        community_description: config.community_description.clone(),
    }))
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<ConfigResponse>, AppError> {
    let mut config = state.config.write().await;

    if let Some(vta_did) = req.vta_did {
        config.vta_did = Some(vta_did);
    }
    if let Some(community_name) = req.community_name {
        config.community_name = Some(community_name);
    }
    if let Some(community_description) = req.community_description {
        config.community_description = Some(community_description);
    }

    config.save()?;

    Ok(Json(ConfigResponse {
        vta_did: config.vta_did.clone(),
        community_name: config.community_name.clone(),
        community_description: config.community_description.clone(),
    }))
}
