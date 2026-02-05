mod health;
pub mod keys;

use axum::Router;
use axum::routing::{get, post};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::health))
        .route("/keys", post(keys::create_key))
        .route(
            "/keys/{key_id}",
            get(keys::get_key)
                .delete(keys::invalidate_key)
                .patch(keys::rename_key),
        )
}
