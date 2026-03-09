use crate::db::models::WsEvent;
use crate::state::AppState;
use super::{Anomaly, AnomalyType, Sentinel};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ────────────────────────── Attack Timeline ──────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTimelineEvent {
    pub timestamp: i64,
    pub event_type: String,
    pub entity_id: String,
    pub description: String,
    pub mitre_tactic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTimeline {
    pub events: Vec<AttackTimelineEvent>,
    pub entry_point: Option<String>,
    pub attack_duration_secs: i64,
}

// ────────────────────────── Security Incident ──────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: String,
    pub org_id: String,
    pub severity: String,
    pub attack_type: String,
    pub entry_point_entity_id: Option<String>,
    pub affected_entities: Vec<String>,
    pub attack_timeline: AttackTimeline,
    pub mitre_ttps: Vec<String>,
    pub vulnerability: Option<String>,
    pub remediation: Option<String>,
    pub status: String,     // "open" | "investigating" | "resolved"
    pub detected_at: i64,
    pub resolved_at: Option<i64>,
}

// ────────────────────────── Threat Response ──────────────────────────

/// Agentic threat response when a CRITICAL anomaly is detected.
pub async fn activate_threat_response(
    state: &Arc<AppState>,
    sentinel: &Arc<Sentinel>,
    anomaly: &Anomaly,
) {
    let entity_id = &anomaly.entity_id;

    tracing::warn!(
        "THREAT RESPONSE: Activated for entity {} — {:?}",
        entity_id, anomaly.anomaly_type
    );

    // 1. Immediately quarantine the flagged entity
    let sessions_killed = quarantine_entity(state, entity_id).await;

    // Broadcast quarantine event
    state.hub.broadcast(WsEvent::EntityQuarantined {
        entity_id: entity_id.clone(),
        reason: anomaly.description.clone(),
        active_sessions_killed: sessions_killed,
        ts: chrono::Utc::now().timestamp(),
    });

    // 2. Reconstruct attack chain from audit history
    let timeline = reconstruct_attack_chain(state, entity_id).await;

    // 3. Map to MITRE ATT&CK tactics
    let mitre_ttps = map_to_mitre(&anomaly.anomaly_type);

    // 4. Determine attack type
    let attack_type = classify_attack(&anomaly.anomaly_type);

    // 5. Find affected entities
    let affected = find_affected_entities(state, entity_id).await;

    // 6. Generate remediation guidance
    let remediation = generate_remediation(&anomaly.anomaly_type, entity_id);

    // 7. Create security incident
    let incident = SecurityIncident {
        id: uuid::Uuid::new_v4().to_string(),
        org_id: "system".to_string(),
        severity: "critical".to_string(),
        attack_type: attack_type.clone(),
        entry_point_entity_id: Some(entity_id.clone()),
        affected_entities: affected.clone(),
        attack_timeline: timeline,
        mitre_ttps: mitre_ttps.clone(),
        vulnerability: detect_vulnerability(&anomaly.anomaly_type),
        remediation: Some(remediation),
        status: "open".to_string(),
        detected_at: anomaly.detected_at,
        resolved_at: None,
    };

    // Store incident in DB
    let timeline_json = serde_json::to_string(&incident.attack_timeline).unwrap_or_default();
    let affected_json = serde_json::to_string(&incident.affected_entities).unwrap_or_default();
    let mitre_json = serde_json::to_string(&incident.mitre_ttps).unwrap_or_default();

    let _ = sqlx::query(
        "INSERT INTO security_incidents (id, org_id, severity, attack_type, entry_point_entity_id, affected_entities, attack_timeline, mitre_ttps, vulnerability, remediation, status, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&incident.id)
    .bind(&incident.org_id)
    .bind(&incident.severity)
    .bind(&incident.attack_type)
    .bind(&incident.entry_point_entity_id)
    .bind(&affected_json)
    .bind(&timeline_json)
    .bind(&mitre_json)
    .bind(&incident.vulnerability)
    .bind(&incident.remediation)
    .bind(&incident.status)
    .bind(incident.detected_at)
    .execute(state.db.inner())
    .await;

    // Store in memory
    sentinel.incidents.lock().await.push(incident.clone());

    // 8. Broadcast threat incident
    state.hub.broadcast(WsEvent::ThreatIncident {
        incident_id: incident.id.clone(),
        severity: "critical".to_string(),
        attack_type,
        entities_affected: affected.len() as u32,
        summary: anomaly.description.clone(),
        ts: chrono::Utc::now().timestamp(),
    });

    // 9. Broadcast admin alert
    state.hub.broadcast(WsEvent::Alert {
        alert_type: "ThreatResponse".to_string(),
        severity: "critical".to_string(),
        entity_id: Some(entity_id.clone()),
        description: format!(
            "Threat response activated: entity {} quarantined, {} sessions killed, {} entities affected",
            entity_id, sessions_killed, affected.len()
        ),
        recommended_action: "Review incident details and confirm remediation".to_string(),
        ts: chrono::Utc::now().timestamp(),
    });

    state.hub.log(
        "CRITICAL",
        &format!(
            "Threat response complete: entity={} sessions_killed={} affected={} incident={}",
            entity_id, sessions_killed, affected.len(), incident.id
        ),
    );
}

/// Quarantine an entity — revoke all active sessions.
async fn quarantine_entity(state: &Arc<AppState>, entity_id: &str) -> u32 {
    let pool = state.db.inner();

    // Mark entity as quarantined
    let _ = sqlx::query("UPDATE entities SET quarantined = 1 WHERE id = ?")
        .bind(entity_id)
        .execute(pool)
        .await;

    // Revoke all active sessions involving this entity
    let result = sqlx::query(
        "UPDATE sessions SET status = 'revoked', ended_at = ?, close_reason = 'quarantine_threat_response' WHERE (source_entity_id = ? OR dest_entity_id = ?) AND status = 'active'"
    )
    .bind(chrono::Utc::now().timestamp())
    .bind(entity_id)
    .bind(entity_id)
    .execute(pool)
    .await;

    result.map(|r| r.rows_affected() as u32).unwrap_or(0)
}

/// Reconstruct the attack chain from audit history.
async fn reconstruct_attack_chain(state: &Arc<AppState>, entity_id: &str) -> AttackTimeline {
    let pool = state.db.inner();
    let one_hour_ago = chrono::Utc::now().timestamp() - 3600;

    use sqlx::Row;
    let events = sqlx::query(
        "SELECT event_type, severity, source_entity_id, description, created_at FROM audit_chain WHERE source_entity_id = ? AND created_at > ? ORDER BY created_at ASC LIMIT 50"
    )
    .bind(entity_id)
    .bind(one_hour_ago)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let timeline_events: Vec<AttackTimelineEvent> = events
        .iter()
        .map(|row| {
            AttackTimelineEvent {
                timestamp: row.get("created_at"),
                event_type: row.get("event_type"),
                entity_id: row.get::<String, _>("source_entity_id"),
                description: row.get("description"),
                mitre_tactic: None,
            }
        })
        .collect();

    let duration = if let (Some(first), Some(last)) = (timeline_events.first(), timeline_events.last()) {
        last.timestamp - first.timestamp
    } else {
        0
    };

    AttackTimeline {
        events: timeline_events,
        entry_point: Some(entity_id.to_string()),
        attack_duration_secs: duration,
    }
}

/// Find entities that communicated with the compromised entity recently.
async fn find_affected_entities(state: &Arc<AppState>, entity_id: &str) -> Vec<String> {
    let pool = state.db.inner();
    let one_hour_ago = chrono::Utc::now().timestamp() - 3600;

    use sqlx::Row;
    sqlx::query(
        "SELECT DISTINCT dest_entity_id FROM sessions WHERE source_entity_id = ? AND started_at > ? UNION SELECT DISTINCT source_entity_id FROM sessions WHERE dest_entity_id = ? AND started_at > ?"
    )
    .bind(entity_id)
    .bind(one_hour_ago)
    .bind(entity_id)
    .bind(one_hour_ago)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .iter()
    .map(|row| row.get::<String, _>(0))
    .collect()
}

/// Map anomaly type to MITRE ATT&CK tactics.
fn map_to_mitre(anomaly_type: &AnomalyType) -> Vec<String> {
    match anomaly_type {
        AnomalyType::LateralMovement => vec![
            "TA0008".to_string(), // Lateral Movement
            "TA0007".to_string(), // Discovery
        ],
        AnomalyType::ExfiltrationPattern => vec![
            "TA0010".to_string(), // Exfiltration
            "TA0009".to_string(), // Collection
        ],
        AnomalyType::ControlSignalSpike => vec![
            "TA0011".to_string(), // Command and Control
            "TA0002".to_string(), // Execution
        ],
        AnomalyType::SessionFrequencySpike => vec![
            "TA0040".to_string(), // Impact
        ],
        AnomalyType::TrustScoreDrop => vec![
            "TA0005".to_string(), // Defense Evasion
        ],
        AnomalyType::IntentDeviation => vec![
            "TA0004".to_string(), // Privilege Escalation
        ],
        AnomalyType::NewPeer => vec![
            "TA0007".to_string(), // Discovery
        ],
    }
}

/// Classify the attack type based on anomaly.
fn classify_attack(anomaly_type: &AnomalyType) -> String {
    match anomaly_type {
        AnomalyType::LateralMovement => "Lateral Movement Attack".to_string(),
        AnomalyType::ExfiltrationPattern => "Data Exfiltration".to_string(),
        AnomalyType::ControlSignalSpike => "Command & Control".to_string(),
        AnomalyType::SessionFrequencySpike => "DDoS / Flood Attack".to_string(),
        AnomalyType::TrustScoreDrop => "Trust Erosion".to_string(),
        AnomalyType::IntentDeviation => "Intent Hijacking".to_string(),
        AnomalyType::NewPeer => "Unauthorized Access".to_string(),
    }
}

/// Detect potential vulnerability based on anomaly.
fn detect_vulnerability(anomaly_type: &AnomalyType) -> Option<String> {
    match anomaly_type {
        AnomalyType::ControlSignalSpike => Some("Insufficient command validation — control signals not rate-limited".to_string()),
        AnomalyType::ExfiltrationPattern => Some("Missing data loss prevention — outbound transfer limits not enforced".to_string()),
        AnomalyType::LateralMovement => Some("Flat network segmentation — entities can reach arbitrary peers".to_string()),
        _ => None,
    }
}

/// Generate remediation guidance.
fn generate_remediation(anomaly_type: &AnomalyType, entity_id: &str) -> String {
    match anomaly_type {
        AnomalyType::LateralMovement => format!(
            "1. Verify entity {} credentials are not compromised\n2. Review all new peer connections in the last hour\n3. Rotate entity keypair\n4. Restrict allowed_intents to Heartbeat only\n5. Enable strict peer validation",
            entity_id
        ),
        AnomalyType::ExfiltrationPattern => format!(
            "1. Block all outbound data transfers from entity {}\n2. Capture and review transferred data\n3. Check for unauthorized data access patterns\n4. Enable DLP rules for sensitive data\n5. Rotate encryption keys",
            entity_id
        ),
        AnomalyType::ControlSignalSpike => format!(
            "1. Revoke all ControlSignal permissions for entity {}\n2. Verify entity firmware/software integrity\n3. Check for C2 beaconing patterns\n4. Isolate from control plane\n5. Conduct forensic analysis",
            entity_id
        ),
        _ => format!(
            "1. Review entity {} activity in audit chain\n2. Verify entity identity and credentials\n3. Monitor for 24 hours before releasing quarantine\n4. Consider rotating entity keypair",
            entity_id
        ),
    }
}
