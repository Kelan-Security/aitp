use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use crate::{auth::OrgId, db::models::Session, error::AppError, state::AppState};

#[derive(serde::Deserialize)]
pub struct SessionQuery { active_only: Option<String> }

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/:id/revoke", post(revoke_session))
}

async fn list_sessions(
    OrgId(org_id): OrgId,
    Query(q): Query<SessionQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Session>>, AppError> {
    let active_only = q.active_only.as_deref() == Some("true");
    let sessions = state.db.get_sessions(&org_id, active_only).await?;
    Ok(Json(sessions))
}

async fn revoke_session(
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // We check if session belongs to org
    let sessions = state.db.get_sessions(&org_id, false).await?;
    if !sessions.iter().any(|s| s.id == id) {
        return Err(AppError::NotFound);
    }

    state.db.close_session(&id, "manual_revoke", 0, 0).await?;

    // Broadcast the revocation
    state.hub.log("WARN", &format!("Session {} explicitly revoked by user", id));
    
    // In real system we'd send a control message to the server node via UDP bridge

    Ok(Json(serde_json::json!({ "success": true })))
}
