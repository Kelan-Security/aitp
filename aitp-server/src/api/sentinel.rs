use axum::{extract::State, routing::get, Json, Router};
use std::sync::Arc;

use crate::auth::OrgId;
use crate::error::AppError;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/sentinel/status", get(status))
        .route("/api/sentinel/anomalies", get(anomalies))
        .route("/api/sentinel/baselines", get(baselines))
}

async fn status(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
) -> Result<Json<serde_json::Value>, AppError> {
    let anomalies = state.sentinel.anomalies.lock().await;

    let twenty_four_h_ago = chrono::Utc::now().timestamp() - 86400;
    let anomalies_24h = anomalies
        .iter()
        .filter(|a| a.detected_at > twenty_four_h_ago)
        .count();

    let critical_24h = anomalies
        .iter()
        .filter(|a| a.detected_at > twenty_four_h_ago)
        .filter(|a| matches!(a.severity, crate::sentinel::AnomalySeverity::Critical))
        .count();

    let learning_count = state.sentinel.baselines.iter()
        .filter(|r| !r.value().learning_complete)
        .count();

    Ok(Json(serde_json::json!({
        "monitoring": state.config.sentinel_enabled,
        "entities_monitored": state.sentinel.baselines.len(),
        "learning_count": learning_count,
        "anomalies_24h": anomalies_24h,
        "critical_24h": critical_24h,
        "auto_quarantine": state.config.auto_quarantine,
    })))
}

async fn anomalies(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
) -> Result<Json<serde_json::Value>, AppError> {
    let anomalies = state.sentinel.anomalies.lock().await;
    let list: Vec<_> = anomalies.iter().rev().take(100).collect();
    Ok(Json(serde_json::json!(list)))
}

async fn baselines(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
) -> Result<Json<serde_json::Value>, AppError> {
    let list: Vec<_> = state.sentinel.baselines.iter()
        .map(|r| r.value().clone())
        .collect();
    Ok(Json(serde_json::json!(list)))
}
