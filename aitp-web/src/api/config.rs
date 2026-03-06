use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use std::sync::Arc;
use crate::{auth::OrgId, db::models::{UpdateAiConfigReq, VerifyKeyReq}, error::AppError, state::AppState};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/config/ai", post(update_ai_config))
        .route("/api/config/ai/verify", post(verify_api_key))
}

async fn update_ai_config(
    OrgId(org_id): OrgId,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateAiConfigReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.update_ai_config(
        &org_id,
        &req.provider,
        &req.model,
        &req.trust_mode,
        req.api_key.as_deref()
    ).await?;

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn verify_api_key(
    OrgId(_org_id): OrgId,
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<VerifyKeyReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    // In a real system, you'd use the provided key to make a test request to the LLM backend
    // to verify if it's valid before saving. For this build, we just simulate success.
    
    // Simulating remote verify...
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    Ok(Json(serde_json::json!({ "valid": true })))
}
