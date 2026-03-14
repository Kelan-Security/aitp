pub mod auth;
pub mod config;
pub mod entities;
pub mod policies;
pub mod sentinel;
pub mod sessions;
pub mod stats;
pub mod threat;

use crate::state::AppState;
use axum::Router;
use tower_http::compression::CompressionLayer;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
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
