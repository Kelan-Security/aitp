// AITP Agentic Threat Response Engine — mod.rs
// Module entry point exposing the agent and its integration with the Sentinel.

pub mod cve;
pub mod gemini_agent;
pub mod mitre;
pub mod types;

pub use gemini_agent::ThreatResponseAgent;

use crate::sentinel::Anomaly;
use crate::state::AppState;
use std::sync::Arc;

/// Activate the agentic threat response for a critical anomaly.
/// Called from the Sentinel when a CRITICAL anomaly is detected.
pub async fn activate_agent(state: &Arc<AppState>, anomaly: &Anomaly) {
    if state.config.gemini_api_key.is_empty() {
        tracing::warn!("Agent activation skipped — no Gemini API key configured");
        // Fall back to rule-based response
        crate::sentinel::threat::activate_threat_response(state, &state.sentinel, anomaly).await;
        return;
    }

    let agent = ThreatResponseAgent::new(
        state.config.gemini_api_key.clone(),
        // Use gemini-2.5-flash for speed in the agentic loop
        state.config.gemini_model.clone(),
        state.db.clone(),
        Arc::new(state.hub.clone()),
        state.config.auto_quarantine,
        state.memory_budget.clone(),
    );

    let report = agent.investigate(anomaly).await;

    // Store the incident in the DB
    let timeline_json = serde_json::to_string(&report.timeline).unwrap_or_default();
    let mitre_json = serde_json::to_string(&report.mitre_ttps).unwrap_or_default();
    let affected_json = serde_json::to_string(&report.affected_entities).unwrap_or_default();
    let runbook_json = serde_json::to_string(&report.remediation_runbook).unwrap_or_default();
    
    match &state.db {
        crate::db::DbPool::Postgres(pool) => {
            let _ = sqlx::query::<sqlx::Postgres>("INSERT INTO security_incidents (id, org_id, severity, attack_type, summary, entry_point_entity_id, affected_entities, attack_timeline, mitre_ttps, vulnerability, remediation, status, confidence, investigation_steps, detected_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)")
                .bind(&report.id).bind(&report.org_id).bind(&report.severity)
                .bind(&report.attack_type).bind(&report.summary).bind(&report.entry_point_entity_id)
                .bind(&affected_json).bind(&timeline_json).bind(&mitre_json)
                .bind(&report.vulnerability).bind(&runbook_json).bind("open")
                .bind(report.confidence).bind(report.investigation_steps as i32).bind(report.detected_at)
                .execute(pool).await;
        }
        crate::db::DbPool::Sqlite(pool) => {
            let _ = sqlx::query::<sqlx::Sqlite>("INSERT INTO security_incidents (id, org_id, severity, attack_type, summary, entry_point_entity_id, affected_entities, attack_timeline, mitre_ttps, vulnerability, remediation, status, confidence, investigation_steps, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&report.id).bind(&report.org_id).bind(&report.severity)
                .bind(&report.attack_type).bind(&report.summary).bind(&report.entry_point_entity_id)
                .bind(&affected_json).bind(&timeline_json).bind(&mitre_json)
                .bind(&report.vulnerability).bind(&runbook_json).bind("open")
                .bind(report.confidence).bind(report.investigation_steps as i32).bind(report.detected_at)
                .execute(pool).await;
        }
    }

    // Store in sentinel memory
    let incident = crate::sentinel::SecurityIncident {
        id: report.id.clone(),
        org_id: report.org_id.clone(),
        severity: report.severity.clone(),
        attack_type: report.attack_type.clone(),
        entry_point_entity_id: report.entry_point_entity_id.clone(),
        affected_entities: report.affected_entities.clone(),
        attack_timeline: crate::sentinel::threat::AttackTimeline {
            events: report
                .timeline
                .iter()
                .map(|t| crate::sentinel::threat::AttackTimelineEvent {
                    timestamp: t.timestamp,
                    event_type: t.event_type.clone(),
                    entity_id: t.entity_id.clone(),
                    description: t.description.clone(),
                    mitre_tactic: None,
                })
                .collect(),
            entry_point: report.entry_point_entity_id.clone(),
            attack_duration_secs: 0,
        },
        mitre_ttps: report.mitre_ttps.iter().map(|t| t.id.clone()).collect(),
        vulnerability: report.vulnerability.clone(),
        remediation: Some(report.remediation_runbook.join("\n")),
        status: "open".to_string(),
        detected_at: report.detected_at,
        resolved_at: None,
    };
    state.sentinel.incidents.lock().await.push(incident);

    // Broadcast to WebSocket
    use crate::db::models::WsEvent;
    state.hub.broadcast(WsEvent::ThreatIncident {
        incident_id: report.id.clone(),
        severity: report.severity.clone(),
        attack_type: report.attack_type.clone(),
        entities_affected: report.affected_entities.len() as u32,
        summary: report.summary.clone(),
        ts: chrono::Utc::now().timestamp(),
    });

    state.hub.log(
        "AI",
        &format!(
            "🤖 Incident {} — {} (confidence: {:.0}%, {} steps, {} actions)",
            &report.id[..report.id.len().min(8)],
            &report.summary[..report.summary.len().min(60)],
            report.confidence * 100.0,
            report.investigation_steps,
            report.automated_actions_taken.len(),
        ),
    );
}
