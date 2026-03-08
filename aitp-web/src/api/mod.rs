pub mod auth;
pub mod config;
pub mod events;
pub mod federation;
pub mod nodes;
pub mod sentinel;
pub mod sessions;
pub mod stats;

use axum::Router;

pub fn router() -> Router<std::sync::Arc<crate::state::AppState>> {
    Router::new()
        .merge(auth::router())
        .merge(nodes::router())
        .merge(sessions::router())
        .merge(events::router())
        .merge(config::router())
        .merge(stats::router())
        .merge(sentinel::router())
        .merge(federation::router())
}
