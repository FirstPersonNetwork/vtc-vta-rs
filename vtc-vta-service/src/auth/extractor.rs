use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;

use crate::acl::Role;
use crate::auth::session::{SessionState, get_session};
use crate::error::AppError;
use crate::server::AppState;

/// Extracted from a valid JWT Bearer token on protected routes.
///
/// Add this as a handler parameter to require authentication:
/// ```ignore
/// async fn handler(_auth: AuthClaims, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AuthClaims {
    pub did: String,
    pub session_id: String,
    pub role: Role,
}

impl FromRequestParts<AppState> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract Bearer token from Authorization header
        let TypedHeader(auth) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::Unauthorized("missing or invalid Authorization header".into()))?;

        let token = auth.token();

        // Decode and validate JWT
        let jwt_keys = state
            .jwt_keys
            .as_ref()
            .ok_or_else(|| AppError::Unauthorized("auth not configured".into()))?;

        let claims = jwt_keys.decode(token)?;

        // Verify session exists and is authenticated
        let sessions = state.store.keyspace("sessions")?;
        let session = get_session(&sessions, &claims.session_id)
            .await?
            .ok_or_else(|| AppError::Unauthorized("session not found".into()))?;

        if session.state != SessionState::Authenticated {
            return Err(AppError::Unauthorized("session not authenticated".into()));
        }

        let role = Role::from_str(&claims.role)?;

        Ok(AuthClaims {
            did: claims.sub,
            session_id: claims.session_id,
            role,
        })
    }
}

/// Extractor that requires the caller to have Admin or Initiator role.
///
/// Use on endpoints that manage ACL entries and other management tasks:
/// ```ignore
/// async fn handler(auth: ManageAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct ManageAuth(pub AuthClaims);

impl FromRequestParts<AppState> for ManageAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin | Role::Initiator => Ok(ManageAuth(claims)),
            _ => Err(AppError::Forbidden(
                "admin or initiator role required".into(),
            )),
        }
    }
}

/// Extractor that requires the caller to have Admin role.
///
/// Use on endpoints that modify configuration, create/delete keys, etc.:
/// ```ignore
/// async fn handler(auth: AdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AdminAuth(pub AuthClaims);

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin => Ok(AdminAuth(claims)),
            _ => Err(AppError::Forbidden("admin role required".into())),
        }
    }
}
