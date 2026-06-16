use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;

use crate::auth::OrgId;
use crate::error::AppError;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/threats", get(list_threats))
        .route("/api/threats/:id", get(get_threat))
        .route("/api/threats/:id/resolve", post(resolve_threat))
}

async fn list_threats(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
) -> Result<Json<serde_json::Value>, AppError> {
    let incidents = state.db.get_incidents(&org_id).await?;
    Ok(Json(serde_json::json!(incidents)))
}

async fn get_threat(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let incident = state
        .db
        .get_incident(&id)
        .await
        .map_err(|_| AppError::NotFound)?;

    // Parse the JSON fields for richer response
    let timeline: serde_json::Value =
        serde_json::from_str(&incident.attack_timeline).unwrap_or(serde_json::Value::Null);
    let affected: serde_json::Value =
        serde_json::from_str(&incident.affected_entities).unwrap_or(serde_json::Value::Null);
    let mitre: serde_json::Value =
        serde_json::from_str(&incident.mitre_ttps).unwrap_or(serde_json::Value::Null);

    Ok(Json(serde_json::json!({
        "id": incident.id,
        "org_id": incident.org_id,
        "severity": incident.severity,
        "attack_type": incident.attack_type,
        "entry_point_entity_id": incident.entry_point_entity_id,
        "affected_entities": affected,
        "attack_timeline": timeline,
        "mitre_ttps": mitre,
        "vulnerability": incident.vulnerability,
        "remediation": incident.remediation,
        "status": incident.status,
        "detected_at": incident.detected_at,
        "resolved_at": incident.resolved_at,
    })))
}

async fn resolve_threat(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let affected = state.db.resolve_incident(&id).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }

    let _ = state
        .db
        .insert_audit(
            &org_id,
            "IncidentResolved",
            "info",
            None,
            None,
            &format!("Security incident {} resolved", id),
            Some("{}"),
        )
        .await;

    state
        .hub
        .log("INFO", &format!("Security incident {} resolved", id));

    Ok(Json(
        serde_json::json!({ "status": "resolved", "incident_id": id }),
    ))
}
