mod acl;
mod auth;
mod config;
mod health;
pub mod keys;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::health))
        .nest(
            "/auth",
            Router::new()
                .route("/challenge", post(auth::challenge))
                .route("/", post(auth::authenticate))
                .route("/refresh", post(auth::refresh))
                .route("/credentials", post(auth::generate_credentials))
                .route("/sessions", get(auth::session_list).delete(auth::revoke_sessions_by_did))
                .route("/sessions/{session_id}", delete(auth::revoke_session)),
        )
        .route(
            "/config",
            get(config::get_config).patch(config::update_config),
        )
        .route("/keys", post(keys::create_key))
        .route(
            "/keys/{key_id}",
            get(keys::get_key)
                .delete(keys::invalidate_key)
                .patch(keys::rename_key),
        )
        .nest(
            "/acl",
            Router::new()
                .route("/", get(acl::list_acl).post(acl::create_acl))
                .route(
                    "/{did}",
                    get(acl::get_acl)
                        .patch(acl::update_acl)
                        .delete(acl::delete_acl),
                ),
        )
}
