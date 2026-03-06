use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use crate::{auth::OrgId, db::models::StatsResp, error::AppError, state::AppState};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/stats", get(get_stats))
}

async fn get_stats(
    OrgId(_org_id): OrgId, // Stats bounded to org level if implemented, but we just use global currently for dashboard
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatsResp>, AppError> {
    let uptime = state.start_time.elapsed().as_secs();
    let stats = state.db.get_stats(uptime).await?;
    Ok(Json(stats))
}
