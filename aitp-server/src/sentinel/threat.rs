use crate::db::models::{AuditEntry, WsEvent};
use crate::sentinel::{Anomaly, AnomalyType, Sentinel};
use crate::state::AppState;
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
    pub status: String, // "open" | "investigating" | "resolved"
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
        entity_id,
        anomaly.anomaly_type
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

    let sql_pg = "INSERT INTO security_incidents (id, org_id, severity, attack_type, entry_point_entity_id, affected_entities, attack_timeline, mitre_ttps, vulnerability, remediation, status, detected_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
    let sql_sq = "INSERT INTO security_incidents (id, org_id, severity, attack_type, entry_point_entity_id, affected_entities, attack_timeline, mitre_ttps, vulnerability, remediation, status, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    match &state.db {
        crate::db::DbPool::Postgres(pool) => {
            let _ = sqlx::query(sql_pg)
                .bind(&incident.id).bind(&incident.org_id).bind(&incident.severity)
                .bind(&incident.attack_type).bind(&incident.entry_point_entity_id)
                .bind(&affected_json).bind(&timeline_json).bind(&mitre_json)
                .bind(&incident.vulnerability).bind(&incident.remediation)
                .bind(&incident.status).bind(incident.detected_at)
                .execute(pool).await;
        }
        crate::db::DbPool::Sqlite(pool) => {
            let _ = sqlx::query(sql_sq)
                .bind(&incident.id).bind(&incident.org_id).bind(&incident.severity)
                .bind(&incident.attack_type).bind(&incident.entry_point_entity_id)
                .bind(&affected_json).bind(&timeline_json).bind(&mitre_json)
                .bind(&incident.vulnerability).bind(&incident.remediation)
                .bind(&incident.status).bind(incident.detected_at)
                .execute(pool).await;
        }
    }

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
            entity_id,
            sessions_killed,
            affected.len(),
            incident.id
        ),
    );
}

/// Quarantine an entity — revoke all active sessions.
async fn quarantine_entity(state: &Arc<AppState>, entity_id: &str) -> u32 {
    let mut updated_rows = 0;
    
    match &state.db {
        crate::db::DbPool::Postgres(pool) => {
            let _ = sqlx::query("UPDATE entities SET quarantined = 1 WHERE id = $1")
                .bind(entity_id).execute(pool).await;
            
            let result = sqlx::query(
                "UPDATE sessions SET status = 'revoked', ended_at = $1, close_reason = 'quarantine_threat_response' WHERE (source_entity_id = $2 OR dest_entity_id = $3) AND status = 'active'"
            )
            .bind(chrono::Utc::now().timestamp()).bind(entity_id).bind(entity_id)
            .execute(pool).await;
            
            if let Ok(r) = result { updated_rows = r.rows_affected() as u32; }
        }
        crate::db::DbPool::Sqlite(pool) => {
            let _ = sqlx::query("UPDATE entities SET quarantined = 1 WHERE id = ?")
                .bind(entity_id).execute(pool).await;
            
            let result = sqlx::query(
                "UPDATE sessions SET status = 'revoked', ended_at = ?, close_reason = 'quarantine_threat_response' WHERE (source_entity_id = ? OR dest_entity_id = ?) AND status = 'active'"
            )
            .bind(chrono::Utc::now().timestamp()).bind(entity_id).bind(entity_id)
            .execute(pool).await;
            
            if let Ok(r) = result { updated_rows = r.rows_affected() as u32; }
        }
    }
    updated_rows
}

async fn reconstruct_attack_chain(state: &Arc<AppState>, entity_id: &str) -> AttackTimeline {
    let one_hour_ago = chrono::Utc::now().timestamp() - 3600;

    use sqlx::Row;
    let events: Vec<AuditEntry> = match &state.db {
        crate::db::DbPool::Postgres(pool) => {
            sqlx::query("SELECT * FROM audit_chain WHERE source_entity_id = $1 AND created_at > $2 ORDER BY created_at ASC LIMIT 50")
                .bind(entity_id).bind(one_hour_ago)
                .fetch_all(pool).await.unwrap_or_default()
                .into_iter()
                .map(|r| AuditEntry {
                    id: r.get("id"),
                    org_id: r.get("org_id"),
                    event_type: r.get("event_type"),
                    severity: r.get("severity"),
                    source_entity_id: r.get("source_entity_id"),
                    session_id: r.get("session_id"),
                    description: r.get("description"),
                    metadata: r.get("metadata"),
                    prev_hash: r.get("prev_hash"),
                    entry_hash: r.get("entry_hash"),
                    created_at: r.get("created_at"),
                })
                .collect()
        }
        crate::db::DbPool::Sqlite(pool) => {
            sqlx::query("SELECT * FROM audit_chain WHERE source_entity_id = ? AND created_at > ? ORDER BY created_at ASC LIMIT 50")
                .bind(entity_id).bind(one_hour_ago)
                .fetch_all(pool).await.unwrap_or_default()
                .into_iter()
                .map(|r| AuditEntry {
                    id: r.get("id"),
                    org_id: r.get("org_id"),
                    event_type: r.get("event_type"),
                    severity: r.get("severity"),
                    source_entity_id: r.get("source_entity_id"),
                    session_id: r.get("session_id"),
                    description: r.get("description"),
                    metadata: r.get("metadata"),
                    prev_hash: r.get("prev_hash"),
                    entry_hash: r.get("entry_hash"),
                    created_at: r.get("created_at"),
                })
                .collect()
        }
    };

    let timeline_events: Vec<AttackTimelineEvent> = events
        .iter()
        .map(|row| AttackTimelineEvent {
            timestamp: row.created_at,
            event_type: row.event_type.clone(),
            entity_id: row.source_entity_id.clone().unwrap_or_default(),
            description: row.description.clone(),
            mitre_tactic: None,
        })
        .collect();

    let duration =
        if let (Some(first), Some(last)) = (timeline_events.first(), timeline_events.last()) {
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
    let one_hour_ago = chrono::Utc::now().timestamp() - 3600;
    let mut affected = Vec::new();

    use sqlx::Row;
    match &state.db {
        crate::db::DbPool::Postgres(pool) => {
            if let Ok(rows) = sqlx::query(
                "SELECT DISTINCT dest_entity_id FROM sessions WHERE source_entity_id = $1 AND started_at > $2 UNION SELECT DISTINCT source_entity_id FROM sessions WHERE dest_entity_id = $3 AND started_at > $4"
            )
            .bind(entity_id).bind(one_hour_ago).bind(entity_id).bind(one_hour_ago)
            .fetch_all(pool).await {
                affected = rows.iter().map(|row| row.get::<String, _>(0)).collect();
            }
        }
        crate::db::DbPool::Sqlite(pool) => {
            if let Ok(rows) = sqlx::query(
                "SELECT DISTINCT dest_entity_id FROM sessions WHERE source_entity_id = ? AND started_at > ? UNION SELECT DISTINCT source_entity_id FROM sessions WHERE dest_entity_id = ? AND started_at > ?"
            )
            .bind(entity_id).bind(one_hour_ago).bind(entity_id).bind(one_hour_ago)
            .fetch_all(pool).await {
                affected = rows.iter().map(|row| row.get::<String, _>(0)).collect();
            }
        }
    }
    affected
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
        AnomalyType::ControlSignalSpike => {
            Some("Insufficient command validation — control signals not rate-limited".to_string())
        }
        AnomalyType::ExfiltrationPattern => {
            Some("Missing data loss prevention — outbound transfer limits not enforced".to_string())
        }
        AnomalyType::LateralMovement => {
            Some("Flat network segmentation — entities can reach arbitrary peers".to_string())
        }
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
