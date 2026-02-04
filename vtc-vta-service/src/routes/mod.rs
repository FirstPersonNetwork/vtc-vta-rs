mod health;

use axum::Router;
use axum::routing::get;

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(health::health))
}
