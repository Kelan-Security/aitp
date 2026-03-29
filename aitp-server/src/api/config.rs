use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;

use crate::auth::OrgId;
use crate::db::models::*;
use crate::error::AppError;
use crate::state::AppState;
use crate::trust::gemini::GeminiTrustEngine;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/config/ai", post(update_ai_config))
        .route("/api/config/verify-key", post(verify_key))
        .route("/api/config/ws-url", get(ws_url))
}

async fn update_ai_config(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Json(req): Json<UpdateAiConfigReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trust_mode = req.trust_mode.as_deref().unwrap_or("hybrid");
    let api_key_enc = req.api_key.as_deref();

    state
        .db
        .update_org_ai_config(&org_id, api_key_enc, trust_mode)
        .await?;

    state.hub.log(
        "INFO",
        &format!("AI config updated: trust_mode={}", trust_mode),
    );

    Ok(Json(serde_json::json!({
        "status": "updated",
        "trust_mode": trust_mode,
    })))
}

async fn verify_key(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Json(req): Json<VerifyKeyReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let engine = GeminiTrustEngine::new(&req.api_key, &req.model);

    match engine.verify_key().await {
        Ok(result) => {
            let _ = state
                .db
                .insert_audit(
                    &org_id,
                    "AiKeyVerified",
                    "info",
                    None,
                    None,
                    &format!("Gemini API key verified — model: {}", req.model),
                    Some("{}"),
                )
                .await;

            state.hub.log(
                "INFO",
                &format!(
                    "Gemini key verified — model={} score={}",
                    req.model, result.trust_score
                ),
            );

            Ok(Json(serde_json::json!({
                "status": "verified",
                "provider": req.provider,
                "model": req.model,
                "test_evaluation": {
                    "trust_score": result.trust_score,
                    "verdict": result.verdict.as_str(),
                    "reasoning": result.reasoning,
                    "confidence": result.confidence,
                    "evaluation_ms": result.evaluation_ms,
                }
            })))
        }
        Err(e) => {
            state
                .hub
                .log("ERROR", &format!("Gemini key verification failed: {}", e));
            Err(AppError::BadRequest(format!(
                "API key verification failed: {}",
                e
            )))
        }
    }
}

/// GET /api/config/ws-url
/// Returns the WebSocket base URL — ws:// in HTTP mode, wss:// in HTTPS mode.
/// Clients read this endpoint to auto-configure their WebSocket connection.
async fn ws_url(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let (scheme, port) = if state.config.tls_enabled() {
        ("wss", 443u16)
    } else {
        ("ws", state.config.http_port)
    };
    let url = format!("{}://localhost:{}/ws", scheme, port);
    Json(serde_json::json!({ "ws_url": url }))
}
