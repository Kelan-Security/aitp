use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::OrgId;
use crate::db::models::*;
use crate::error::AppError;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/:id", get(get_session))
        .route("/api/sessions/:id/revoke", post(revoke_session))
}

#[derive(Deserialize)]
pub struct SessionQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Query(q): Query<SessionQuery>,
) -> Result<Json<Vec<Session>>, AppError> {
    let limit = q.limit.unwrap_or(50);
    let sessions = state
        .db
        .get_sessions(&org_id, q.status.as_deref(), limit)
        .await?;
    Ok(Json(sessions))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<Session>, AppError> {
    let session = state
        .db
        .get_session(&id)
        .await
        .map_err(|_| AppError::NotFound)?;
    Ok(Json(session))
}

async fn revoke_session(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let affected = state.db.revoke_session(&id).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }

    let _ = state
        .db
        .insert_audit(
            &org_id,
            "SessionRevoked",
            "warning",
            None,
            Some(&id),
            &format!("Session {} manually revoked", id),
            Some("{}"),
        )
        .await;

    state.hub.broadcast(WsEvent::SessionKilled {
        session_id: id.clone(),
        entity_id: String::new(),
        reason: "Manual revoke via API".to_string(),
        verdict: "Revoked".to_string(),
        ts: chrono::Utc::now().timestamp(),
    });

    Ok(Json(
        serde_json::json!({ "status": "revoked", "session_id": id }),
    ))
}
