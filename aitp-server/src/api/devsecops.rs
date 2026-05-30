use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use crate::error::AppError;
use crate::state::AppState;
use crate::db::models::Session;
use serde::{Deserialize, Serialize};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/ebpf/status", get(ebpf_status))
        .route("/api/verdicts", get(verdicts))
        .route("/api/trust/evaluate", post(trust_evaluate))
        .route("/api/simulate/run", post(simulate_run))
        .route("/api/simulate/toggle", post(simulate_toggle))
        .route("/api/sentinel/events", get(sentinel_events))
        .route("/api/enroll", get(enroll_fail))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "healthy", "version": "0.3.0" }))
}

async fn sentinel_events() -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}

async fn enroll_fail() -> impl axum::response::IntoResponse {
    axum::http::StatusCode::UNAUTHORIZED
}

async fn ebpf_status(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let ebpf_stats = state.enforcer.stats().await.unwrap_or_default();
    Json(serde_json::json!({
        "status": "ok",
        "mode": format!("{:?}", ebpf_stats.mode).to_lowercase()
    }))
}

async fn verdicts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Get last 100 sessions
    let sessions: Vec<Session> = match &state.db {
        crate::db::DbPool::Postgres(p) => {
            sqlx::query_as("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 100")
                .fetch_all(p)
                .await?
        }
        crate::db::DbPool::Sqlite(p) => {
            sqlx::query_as("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 100")
                .fetch_all(p)
                .await?
        }
    };

    let list: Vec<serde_json::Value> = sessions.into_iter().map(|s| {
        let mut v = serde_json::to_value(&s).unwrap();
        let is_sim = s.close_reason.as_deref() == Some("simulation") || s.anomaly_flags.contains("simulation");
        v["simulation"] = serde_json::json!(is_sim);
        v
    }).collect();

    Ok(Json(serde_json::json!({ "verdicts": list })))
}

#[derive(Debug, Deserialize)]
pub struct TrustEvaluateReq {
    pub entity_id: String,
    pub intent: String,
    pub session_id: String,
    pub anomalies: Option<Vec<String>>,
}

async fn trust_evaluate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TrustEvaluateReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    use crate::trust::SessionContext;

    let anomalies = req.anomalies.unwrap_or_default();

    let ctx = SessionContext {
        source_entity_id: req.entity_id.clone(),
        org_id: "test-org".to_string(),
        source_entity_type: "client".to_string(),
        source_department: Some("engineering".to_string()),
        source_clearance: 1,
        dest_entity_id: "dest-server".to_string(),
        dest_entity_type: "server".to_string(),
        intent: req.intent.clone(),
        entity_age_hours: 24.0,
        session_count_24h: 5,
        avg_trust_score: 120.0,
        known_peer: true,
        behavioral_flags: anomalies.clone(),
        time_of_day_hour: 12,
    };

    let result = state.trust_engine.evaluate(&ctx).await;

    // Record the session in DB
    let session = Session {
        id: req.session_id.clone(),
        org_id: "test-org".to_string(),
        source_entity_id: req.entity_id.clone(),
        dest_entity_id: "dest-server".to_string(),
        intent: req.intent.clone(),
        trust_score: result.trust_score as i64,
        verdict: result.verdict.as_str().to_string(),
        ai_reasoning: Some(result.reasoning.clone()),
        ai_latency_ms: Some(result.evaluation_ms),
        status: "closed".to_string(),
        bytes_tx: 0,
        bytes_rx: 0,
        anomaly_flags: anomalies.join(","),
        started_at: chrono::Utc::now().timestamp(),
        ended_at: Some(chrono::Utc::now().timestamp()),
        close_reason: Some("evaluate_endpoint".to_string()),
    };
    state.db.create_session(session).await?;

    Ok(Json(serde_json::json!({
        "entity_id": req.entity_id,
        "intent": req.intent,
        "session_id": req.session_id,
        "anomalies": anomalies,
        "verdict": result.verdict.as_str(),
        "trust_score": result.trust_score,
        "reasoning": result.reasoning,
        "confidence": result.confidence,
    })))
}

#[derive(Debug, Deserialize)]
pub struct SimulateToggleReq {
    pub enabled: Option<bool>,
    pub status: Option<String>,
}

async fn simulate_toggle(
    State(state): State<Arc<AppState>>,
    req: Option<Json<SimulateToggleReq>>,
) -> Json<serde_json::Value> {
    let enable = if let Some(Json(r)) = req {
        if let Some(e) = r.enabled {
            e
        } else if let Some(s) = r.status {
            s == "on" || s == "true"
        } else {
            !state.simulation_active.load(std::sync::atomic::Ordering::Relaxed)
        }
    } else {
        !state.simulation_active.load(std::sync::atomic::Ordering::Relaxed)
    };

    state.simulation_active.store(enable, std::sync::atomic::Ordering::Relaxed);

    if enable {
        // Spawn background task to periodically write simulation verdicts
        let s = state.clone();
        tokio::spawn(async move {
            tracing::info!("Simulation loop started");
            while s.simulation_active.load(std::sync::atomic::Ordering::Relaxed) {
                let session_id = format!("sim-sess-{}", uuid::Uuid::new_v4());
                let entity_id = "sim-entity".to_string();
                let intent = "ModelInference".to_string();

                let ctx = crate::trust::SessionContext {
                    source_entity_id: entity_id.clone(),
                    org_id: "test-org".to_string(),
                    source_entity_type: "client".to_string(),
                    source_department: Some("engineering".to_string()),
                    source_clearance: 1,
                    dest_entity_id: "sim-dest".to_string(),
                    dest_entity_type: "server".to_string(),
                    intent: intent.clone(),
                    entity_age_hours: 12.0,
                    session_count_24h: 3,
                    avg_trust_score: 125.0,
                    known_peer: true,
                    behavioral_flags: vec![],
                    time_of_day_hour: 14,
                };

                let result = s.trust_engine.evaluate(&ctx).await;

                let session = Session {
                    id: session_id,
                    org_id: "test-org".to_string(),
                    source_entity_id: entity_id,
                    dest_entity_id: "sim-dest".to_string(),
                    intent,
                    trust_score: result.trust_score as i64,
                    verdict: result.verdict.as_str().to_string(),
                    ai_reasoning: Some(result.reasoning.clone()),
                    ai_latency_ms: Some(result.evaluation_ms),
                    status: "closed".to_string(),
                    bytes_tx: 0,
                    bytes_rx: 0,
                    anomaly_flags: "simulation".to_string(),
                    started_at: chrono::Utc::now().timestamp(),
                    ended_at: Some(chrono::Utc::now().timestamp()),
                    close_reason: Some("simulation".to_string()),
                };

                let _ = s.db.create_session(session).await;
                tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            }
            tracing::info!("Simulation loop stopped");
        });
    }

    Json(serde_json::json!({
        "status": if enable { "on" } else { "off" },
        "simulation_active": enable
    }))
}

async fn simulate_run(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    use crate::trust::SessionContext;

    let session_id = format!("sim-run-{}", uuid::Uuid::new_v4());
    let entity_id = "sim-run-entity".to_string();
    let intent = "DataSync".to_string();

    let ctx = SessionContext {
        source_entity_id: entity_id.clone(),
        org_id: "test-org".to_string(),
        source_entity_type: "client".to_string(),
        source_department: Some("engineering".to_string()),
        source_clearance: 1,
        dest_entity_id: "sim-dest".to_string(),
        dest_entity_type: "server".to_string(),
        intent: intent.clone(),
        entity_age_hours: 24.0,
        session_count_24h: 10,
        avg_trust_score: 120.0,
        known_peer: true,
        behavioral_flags: vec![],
        time_of_day_hour: 12,
    };

    let result = state.trust_engine.evaluate(&ctx).await;

    // Record it as simulation
    let session = Session {
        id: session_id,
        org_id: "test-org".to_string(),
        source_entity_id: entity_id,
        dest_entity_id: "sim-dest".to_string(),
        intent,
        trust_score: result.trust_score as i64,
        verdict: result.verdict.as_str().to_string(),
        ai_reasoning: Some(result.reasoning.clone()),
        ai_latency_ms: Some(result.evaluation_ms),
        status: "closed".to_string(),
        bytes_tx: 0,
        bytes_rx: 0,
        anomaly_flags: "simulation".to_string(),
        started_at: chrono::Utc::now().timestamp(),
        ended_at: Some(chrono::Utc::now().timestamp()),
        close_reason: Some("simulation".to_string()),
    };
    state.db.create_session(session).await?;

    Ok(Json(serde_json::json!({
        "scenario": "legitimate",
        "verdict": result.verdict.as_str(),
        "trust_score": result.trust_score,
        "reasoning": result.reasoning,
    })))
}
