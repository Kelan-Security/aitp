use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    sentinel::{Anomaly, AnomalySeverity, EntityBaseline},
    state::AppState,
};

#[derive(Serialize)]
pub struct SentinelStatusResp {
    pub learning_entities: usize,
    pub monitored_entities: usize,
    pub anomalies_24h: usize,
    pub critical_24h: usize,
}

#[derive(Deserialize)]
pub struct AnomaliesQuery {
    pub severity: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct ContainReq {
    pub entity_id: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct ContainResp {
    pub success: bool,
    pub message: String,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/sentinel/status", get(status))
        .route("/api/sentinel/anomalies", get(anomalies))
        .route("/api/sentinel/baselines", get(baselines))
        .route("/api/sentinel/contain", post(contain_entity))
}

pub async fn status(State(state): State<Arc<AppState>>) -> Json<SentinelStatusResp> {
    let baselines = state.sentinel.baselines.read().await;
    let log = state.sentinel.anomaly_log.lock().await;

    let monitored_entities = baselines.values().filter(|b| b.learning_complete).count();
    let learning_entities = baselines.len() - monitored_entities;

    let twenty_four_hours_ago = Utc::now().timestamp() - 86400;

    let anomalies_24h = log
        .iter()
        .filter(|a| a.detected_at > twenty_four_hours_ago)
        .count();
    let critical_24h = log
        .iter()
        .filter(|a| {
            a.detected_at > twenty_four_hours_ago && matches!(a.severity, AnomalySeverity::Critical)
        })
        .count();

    Json(SentinelStatusResp {
        learning_entities,
        monitored_entities,
        anomalies_24h,
        critical_24h,
    })
}

pub async fn anomalies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AnomaliesQuery>,
) -> Json<Vec<Anomaly>> {
    let log = state.sentinel.anomaly_log.lock().await;

    let mut filtered: Vec<Anomaly> = log.clone();

    if let Some(sev_str) = &params.severity {
        filtered.retain(|a| {
            let s = match a.severity {
                AnomalySeverity::Info => "info",
                AnomalySeverity::Warning => "warning",
                AnomalySeverity::Alert => "alert",
                AnomalySeverity::Critical => "critical",
            };
            s.eq_ignore_ascii_case(sev_str)
        });
    }

    filtered.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));

    if let Some(l) = params.limit {
        filtered.truncate(l);
    }

    Json(filtered)
}

pub async fn baselines(State(state): State<Arc<AppState>>) -> Json<Vec<EntityBaseline>> {
    let baselines = state.sentinel.baselines.read().await;
    let mut list: Vec<EntityBaseline> = baselines.values().cloned().collect();
    list.sort_by(|a, b| b.session_count.cmp(&a.session_count));
    Json(list)
}

pub async fn contain_entity(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContainReq>,
) -> Json<ContainResp> {
    let _ = sqlx::query(
        "
        INSERT INTO audit_events (id, event_type, severity, entity_id, description, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    ",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind("ManualContainment")
    .bind("critical")
    .bind(&req.entity_id)
    .bind(&format!("Entity manually contained: {}", req.reason))
    .bind(Utc::now().timestamp())
    .execute(state.db.inner())
    .await;

    let _ = sqlx::query(
        "
        UPDATE sessions
        SET status = 'Closed', close_reason = 'contained_by_sentinel'
        WHERE (client_entity_id = $1 OR server_node_id = $1)
        AND status = 'Active'
    ",
    )
    .bind(&req.entity_id)
    .execute(state.db.inner())
    .await;

    let _ = sqlx::query(
        "
        UPDATE client_nodes
        SET trust_score = 0
        WHERE entity_id = $1
    ",
    )
    .bind(&req.entity_id)
    .execute(state.db.inner())
    .await;

    state.hub.alert(
        "Containment",
        "critical",
        &req.entity_id,
        &format!("Entity contained: {}", req.reason),
    );

    Json(ContainResp {
        success: true,
        message: format!("Entity {} has been successfully contained.", req.entity_id),
    })
}
