use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use crate::{auth::OrgId, db::models::AuditEvent, error::AppError, state::AppState};

#[derive(serde::Deserialize)]
pub struct EventQuery { pub limit: Option<i64> }

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/events", get(list_events))
}

async fn list_events(
    OrgId(org_id): OrgId,
    Query(q): Query<EventQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AuditEvent>>, AppError> {
    let limit = q.limit.unwrap_or(100).min(1000);
    let events = state.db.get_recent_events(&org_id, limit).await?;
    Ok(Json(events))
}
