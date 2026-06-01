use axum::{
    extract::{Path, State},
    routing::{get, put},
    Json, Router,
};
use std::sync::Arc;

use crate::auth::OrgId;
use crate::db::models::*;
use crate::error::AppError;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/policies", get(list_policies).post(create_policy))
        .route(
            "/api/policies/:id",
            put(update_policy).delete(delete_policy),
        )
}

async fn list_policies(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
) -> Result<Json<Vec<CommPolicy>>, AppError> {
    let policies = state.db.get_policies(&org_id).await?;
    Ok(Json(policies))
}

async fn create_policy(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Json(req): Json<CreatePolicyReq>,
) -> Result<Json<CommPolicy>, AppError> {
    let policy = CommPolicy {
        id: uuid::Uuid::new_v4().to_string(),
        org_id: org_id.clone(),
        name: req.name,
        source_type: req.source_type,
        dest_type: req.dest_type,
        allowed_intents: serde_json::to_string(&req.allowed_intents).unwrap_or_default(),
        max_sessions_per_hour: req.max_sessions_per_hour,
        require_clearance_match: req
            .require_clearance_match
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(0),
        enabled: 1,
        priority: req.priority.unwrap_or(100),
        created_at: chrono::Utc::now().timestamp(),
    };

    state.db.create_policy(policy.clone()).await?;

    state
        .hub
        .log("INFO", &format!("Policy '{}' created", policy.name));

    Ok(Json(policy))
}

async fn update_policy(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let intents_json = req
        .allowed_intents
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    let affected = state
        .db
        .update_policy(
            &id,
            &org_id,
            req.name.as_deref(),
            req.source_type.as_deref(),
            req.dest_type.as_deref(),
            intents_json.as_deref(),
            req.max_sessions_per_hour,
            req.require_clearance_match
                .map(|b| if b { 1i64 } else { 0 }),
            req.enabled.map(|b| if b { 1i64 } else { 0 }),
            req.priority,
        )
        .await?;

    if affected == 0 {
        return Err(AppError::NotFound);
    }

    Ok(Json(
        serde_json::json!({ "status": "updated", "policy_id": id }),
    ))
}

async fn delete_policy(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let affected = state.db.delete_policy(&id, &org_id).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }

    state.hub.log("WARN", &format!("Policy {} deleted", id));

    Ok(Json(
        serde_json::json!({ "status": "deleted", "policy_id": id }),
    ))
}
