use std::sync::Arc;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::routes;
use crate::store::Store;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub config: Arc<RwLock<AppConfig>>,
}

pub async fn run(config: AppConfig, store: Store) -> Result<(), AppError> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await.map_err(AppError::Io)?;

    let state = AppState {
        store,
        config: Arc::new(RwLock::new(config)),
    };
    let app = routes::router()
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    info!("server listening addr={addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(AppError::Io)?;

    info!("server shut down");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
    }
}
