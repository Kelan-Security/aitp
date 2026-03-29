pub mod crypto;
pub mod auth;
pub mod config;
pub mod entities;
pub mod policies;
pub mod sentinel;
pub mod sessions;
pub mod stats;
pub mod threat;
pub mod middleware;

use crate::state::AppState;
use axum::Router;
use tower_http::compression::CompressionLayer;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .nest("/api/crypto", crypto::router())
        .merge(auth::router())
        .merge(entities::router())
        .merge(sessions::router())
        .merge(sentinel::router())
        .merge(threat::router())
        .merge(policies::router())
        .merge(config::router())
        .merge(stats::router())
        .layer(CompressionLayer::new())
}
