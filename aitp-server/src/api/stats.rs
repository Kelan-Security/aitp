use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use std::sync::Arc;

use crate::auth::OrgId;
use crate::db::models::*;
use crate::error::AppError;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/stats", get(stats))
}

async fn stats(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
) -> Result<Json<StatsResp>, AppError> {
    let uptime = state.start_time.elapsed().as_secs();
    let stats = state.db.get_stats(uptime).await?;
    Ok(Json(stats))
}
