// AITP Agentic Threat Response Engine — gemini_agent.rs
// ReAct (Reasoning + Acting) loop powered by Gemini for autonomous threat investigation.

use super::cve::CveIntelligence;
use super::mitre;
use super::types::*;
use crate::db::DbPool;
use crate::sentinel::{Anomaly, AnomalySeverity};
use crate::ws::WsHub;

use serde_json::Value;
use std::sync::Arc;

const MAX_STEPS: u32 = 20;

const AGENT_SYSTEM_PROMPT: &str = r#"
You are AITP's Autonomous Threat Response Agent.
A CRITICAL security anomaly has been detected. Your job is to investigate it,
understand what happened, and generate a complete incident report.

You reason step by step. For each step, output EXACTLY this JSON format:
{
  "thought": "<your reasoning about what you know and what you need>",
  "action": {
    "action": "<ActionName>",
    ...action parameters...
  }
}

Available actions:
- {"action": "QueryAuditChain", "entity_id": "...", "time_range_start": <unix>, "time_range_end": <unix>, "event_types": ["..."]}
- {"action": "QueryEntityHistory", "entity_id": "..."}
- {"action": "QuerySessionDetails", "session_id": "..."}
- {"action": "QueryRelatedEntities", "entity_id": "...", "time_window_secs": 3600}
- {"action": "SearchCVE", "service_name": "...", "version": "..."}
- {"action": "QueryMitreAttack", "behavior_description": "..."}
- {"action": "GetNetworkTopology"}
- {"action": "QuarantineEntity", "entity_id": "...", "reason": "..."}  [only if clearly compromised, confidence > 0.85]
- {"action": "RevokeSession", "session_id": "...", "reason": "..."}    [only for active malicious sessions]
- {"action": "AlertAdmin", "message": "...", "severity": "CRITICAL|HIGH|MEDIUM"}
- {"action": "GenerateIncidentReport", "summary": "...", "attack_type": "...", "entry_point": "...", "timeline": [...], "mitre_ttps": ["T1078", ...], "vulnerability": "...", "remediation_runbook": ["step1", ...], "confidence": 0.92}

Investigation principles:
1. First understand what anomaly was detected and which entity it involves
2. Query the audit chain around that entity and time period
3. Look for correlated events in other entities
4. Identify the earliest anomalous event (entry point)
5. Trace the lateral movement graph
6. Only QuarantineEntity if confidence > 0.85
7. Always end with GenerateIncidentReport when investigation is complete
8. Be specific about CVEs and remediation steps — no vague advice
"#;

pub struct ThreatResponseAgent {
    api_key: String,
    model: String,
    client: reqwest::Client,
    db: DbPool,
    hub: Arc<WsHub>,
    cve: CveIntelligence,
    auto_quarantine: bool,
}

impl ThreatResponseAgent {
    pub fn new(
        api_key: String,
        model: String,
        db: DbPool,
        hub: Arc<WsHub>,
        auto_quarantine: bool,
    ) -> Self {
        Self {
            api_key,
            model,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            db,
            hub,
            cve: CveIntelligence::new(),
            auto_quarantine,
        }
    }

    /// Run the full agentic investigation loop for a critical anomaly.
    pub async fn investigate(&self, anomaly: &Anomaly) -> AgentIncidentReport {
        let start = std::time::Instant::now();
        let mut steps: Vec<AgentStep> = Vec::new();
        let mut actions_taken: Vec<String> = Vec::new();
        let mut conversation = Vec::<Value>::new();

        self.hub.log(
            "AI",
            &format!(
                "🤖 Threat Response Agent ACTIVATED — investigating {:?} on entity {}",
                anomaly.anomaly_type,
                &anomaly.entity_id[..anomaly.entity_id.len().min(12)]
            ),
        );

        // Initial context message
        let initial_context = format!(
            "ANOMALY DETECTED:\n- Entity ID: {}\n- Type: {:?}\n- Severity: {:?}\n- Description: {}\n- Detected at: {}\n\nBegin your investigation.",
            anomaly.entity_id,
            anomaly.anomaly_type,
            anomaly.severity,
            anomaly.description,
            anomaly.detected_at,
        );

        conversation.push(serde_json::json!({
            "role": "user",
            "parts": [{ "text": initial_context }]
        }));

        for step_num in 1..=MAX_STEPS {
            // Call Gemini
            let response = match self.call_gemini(&conversation).await {
                Ok(text) => text,
                Err(e) => {
                    tracing::error!("Agent step {} Gemini call failed: {}", step_num, e);
                    // Fallback: generate report from what we have
                    break;
                }
            };

            // Parse THOUGHT + ACTION
            let (thought, action) = match self.parse_agent_response(&response) {
                Ok((t, a)) => (t, a),
                Err(e) => {
                    tracing::warn!(
                        "Agent step {} parse error: {} — raw: {}",
                        step_num,
                        e,
                        &response[..response.len().min(200)]
                    );
                    break;
                }
            };

            self.hub.log(
                "AI",
                &format!("  Step {}: {}", step_num, &thought[..thought.len().min(80)]),
            );

            // Check for terminal action
            let is_terminal = matches!(action, AgentAction::GenerateIncidentReport { .. });

            // Execute the action
            let observation = self.execute_action(&action, &mut actions_taken).await;

            steps.push(AgentStep {
                step_number: step_num,
                thought: thought.clone(),
                action: action.clone(),
                observation: observation.clone(),
            });

            // Add to conversation
            conversation.push(serde_json::json!({
                "role": "model",
                "parts": [{ "text": response }]
            }));
            conversation.push(serde_json::json!({
                "role": "user",
                "parts": [{ "text": format!("OBSERVATION:\n{}", observation) }]
            }));

            if is_terminal {
                // Extract the final report from the GenerateIncidentReport action
                if let AgentAction::GenerateIncidentReport {
                    summary,
                    attack_type,
                    entry_point,
                    timeline,
                    mitre_ttps,
                    vulnerability,
                    remediation_runbook,
                    confidence,
                } = action
                {
                    let elapsed = start.elapsed();
                    self.hub.log(
                        "AI",
                        &format!(
                            "🤖 Investigation complete in {} steps ({:.1}s) — confidence: {:.0}%",
                            step_num,
                            elapsed.as_secs_f64(),
                            confidence * 100.0
                        ),
                    );

                    let mitre_mapped: Vec<MitreTtp> = mitre_ttps
                        .iter()
                        .flat_map(|t| mitre::map_behaviors(t))
                        .collect();

                    return AgentIncidentReport {
                        id: uuid::Uuid::new_v4().to_string(),
                        org_id: "system".to_string(),
                        severity: severity_from_anomaly(&anomaly.severity),
                        attack_type,
                        summary,
                        entry_point_entity_id: entry_point,
                        affected_entities: vec![anomaly.entity_id.clone()],
                        timeline,
                        mitre_ttps: mitre_mapped,
                        vulnerability,
                        data_at_risk: vec![],
                        what_attacker_did: steps
                            .iter()
                            .filter(|s| {
                                matches!(
                                    s.action,
                                    AgentAction::QuarantineEntity { .. }
                                        | AgentAction::RevokeSession { .. }
                                )
                            })
                            .map(|s| s.thought.clone())
                            .collect(),
                        what_was_prevented: actions_taken
                            .iter()
                            .filter(|a| a.contains("quarantine") || a.contains("revoke"))
                            .cloned()
                            .collect(),
                        remediation_runbook,
                        confidence,
                        automated_actions_taken: actions_taken.clone(),
                        detected_at: anomaly.detected_at,
                        investigation_steps: step_num,
                        investigation_log: steps,
                    };
                }
            }
        }

        // Fallback: step limit reached or error — generate from available data
        self.hub.log(
            "AI",
            "🤖 Investigation reached step limit — generating report from available evidence",
        );
        self.fallback_report(anomaly, steps, actions_taken)
    }

    async fn call_gemini(&self, conversation: &[Value]) -> Result<String, String> {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let request = serde_json::json!({
            "contents": conversation,
            "systemInstruction": {
                "parts": [{ "text": AGENT_SYSTEM_PROMPT }]
            },
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json"
            }
        });

        let resp = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Gemini request failed: {}", e))?;

        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Gemini {}: {}", s, body));
        }

        let data: Value = resp
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))?;
        let text = data["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        if text.is_empty() {
            return Err("Empty Gemini response".to_string());
        }

        Ok(text)
    }

    fn parse_agent_response(&self, response: &str) -> Result<(String, AgentAction), String> {
        // Find JSON in response
        let json_str = extract_json(response)?;
        let val: Value = serde_json::from_str(&json_str).map_err(|e| {
            format!(
                "JSON parse: {} — input: {}",
                e,
                &json_str[..json_str.len().min(200)]
            )
        })?;

        let thought = val["thought"]
            .as_str()
            .unwrap_or("(no thought)")
            .to_string();
        let action_val = &val["action"];

        let action: AgentAction = serde_json::from_value(action_val.clone())
            .map_err(|e| format!("Action parse: {} — val: {}", e, action_val))?;

        Ok((thought, action))
    }

    async fn execute_action(
        &self,
        action: &AgentAction,
        actions_taken: &mut Vec<String>,
    ) -> String {
        match action {
            AgentAction::QueryAuditChain {
                entity_id,
                time_range_start,
                time_range_end,
                event_types,
            } => {
                self.query_audit_chain(
                    entity_id.as_deref(),
                    *time_range_start,
                    *time_range_end,
                    event_types,
                )
                .await
            }
            AgentAction::QueryEntityHistory { entity_id } => {
                self.query_entity_history(entity_id).await
            }
            AgentAction::QuerySessionDetails { session_id } => {
                self.query_session_details(session_id).await
            }
            AgentAction::QueryRelatedEntities {
                entity_id,
                time_window_secs,
            } => {
                self.query_related_entities(entity_id, *time_window_secs)
                    .await
            }
            AgentAction::SearchCVE {
                service_name,
                version,
            } => {
                let results = self.cve.lookup(service_name, version);
                if results.is_empty() {
                    format!("No CVEs found for {} v{}", service_name, version)
                } else {
                    serde_json::to_string_pretty(&results).unwrap_or_default()
                }
            }
            AgentAction::QueryMitreAttack {
                behavior_description,
            } => {
                let ttps = mitre::map_behaviors(behavior_description);
                serde_json::to_string_pretty(&ttps).unwrap_or_default()
            }
            AgentAction::GetNetworkTopology {} => self.get_network_topology().await,
            AgentAction::QuarantineEntity { entity_id, reason } => {
                if self.auto_quarantine {
                    let _ = self.db.quarantine_entity(entity_id).await;
                    actions_taken.push(format!(
                        "Quarantined entity {} — {}",
                        &entity_id[..entity_id.len().min(12)],
                        reason
                    ));
                    self.hub.log(
                        "CRITICAL",
                        &format!(
                            "🔒 Agent quarantined entity {}",
                            &entity_id[..entity_id.len().min(12)]
                        ),
                    );
                    format!("Entity {} quarantined successfully", entity_id)
                } else {
                    actions_taken.push(format!(
                        "RECOMMENDED quarantine for {} (auto-quarantine disabled)",
                        &entity_id[..entity_id.len().min(12)]
                    ));
                    "Auto-quarantine is DISABLED. Entity flagged for manual review.".to_string()
                }
            }
            AgentAction::RevokeSession { session_id, reason } => {
                let _ = self.db.revoke_session(session_id).await;
                actions_taken.push(format!(
                    "Revoked session {} — {}",
                    &session_id[..session_id.len().min(12)],
                    reason
                ));
                format!("Session {} revoked", session_id)
            }
            AgentAction::BlockIP {
                ip_address,
                reason,
                duration_secs,
            } => {
                actions_taken.push(format!(
                    "Block IP {} for {}s — {}",
                    ip_address, duration_secs, reason
                ));
                self.hub.log(
                    "WARN",
                    &format!("🚫 Agent blocked IP {} for {}s", ip_address, duration_secs),
                );
                format!("IP {} blocked for {} seconds", ip_address, duration_secs)
            }
            AgentAction::AlertAdmin { message, severity } => {
                actions_taken.push(format!(
                    "Alert [{severity}]: {}",
                    &message[..message.len().min(60)]
                ));
                self.hub.log(
                    &severity.to_uppercase(),
                    &format!("📢 Agent alert: {}", message),
                );
                format!("Admin alerted: [{}] {}", severity, message)
            }
            AgentAction::GenerateIncidentReport { summary, .. } => {
                format!(
                    "Incident report generated: {}",
                    &summary[..summary.len().min(100)]
                )
            }
        }
    }

    // ─── Tool implementations ────────────────────────────────────────────────

    async fn query_audit_chain(
        &self,
        entity_id: Option<&str>,
        start: i64,
        end: i64,
        _event_types: &[String],
    ) -> String {
        use sqlx::Row;

        let entries: Vec<Value> = match &self.db {
            crate::db::DbPool::Postgres(pool) => {
                let rows = if let Some(eid) = entity_id {
                    sqlx::query(
                        "SELECT event_type, severity, source_entity_id, description, created_at FROM audit_chain WHERE source_entity_id = $1 AND created_at BETWEEN $2 AND $3 ORDER BY created_at DESC LIMIT 30"
                    )
                    .bind(eid).bind(start).bind(end)
                    .fetch_all(pool).await.unwrap_or_default()
                } else {
                    sqlx::query(
                        "SELECT event_type, severity, source_entity_id, description, created_at FROM audit_chain WHERE created_at BETWEEN $1 AND $2 ORDER BY created_at DESC LIMIT 30"
                    )
                    .bind(start).bind(end)
                    .fetch_all(pool).await.unwrap_or_default()
                };
                rows.into_iter().map(|r| {
                    serde_json::json!({
                        "event_type": r.get::<String, _>("event_type"),
                        "severity": r.get::<String, _>("severity"),
                        "entity_id": r.get::<Option<String>, _>("source_entity_id"),
                        "description": r.get::<String, _>("description"),
                        "created_at": r.get::<i64, _>("created_at"),
                    })
                }).collect()
            }
            crate::db::DbPool::Sqlite(pool) => {
                let rows = if let Some(eid) = entity_id {
                    sqlx::query(
                        "SELECT event_type, severity, source_entity_id, description, created_at FROM audit_chain WHERE source_entity_id = ? AND created_at BETWEEN ? AND ? ORDER BY created_at DESC LIMIT 30"
                    )
                    .bind(eid).bind(start).bind(end)
                    .fetch_all(pool).await.unwrap_or_default()
                } else {
                    sqlx::query(
                        "SELECT event_type, severity, source_entity_id, description, created_at FROM audit_chain WHERE created_at BETWEEN ? AND ? ORDER BY created_at DESC LIMIT 30"
                    )
                    .bind(start).bind(end)
                    .fetch_all(pool).await.unwrap_or_default()
                };
                rows.into_iter().map(|r| {
                    serde_json::json!({
                        "event_type": r.get::<String, _>("event_type"),
                        "severity": r.get::<String, _>("severity"),
                        "entity_id": r.get::<Option<String>, _>("source_entity_id"),
                        "description": r.get::<String, _>("description"),
                        "created_at": r.get::<i64, _>("created_at"),
                    })
                }).collect()
            }
        };

        if entries.is_empty() {
            return "No audit events found in the specified time range.".to_string();
        }

        serde_json::to_string_pretty(&entries).unwrap_or_default()
    }

    async fn query_entity_history(&self, entity_id: &str) -> String {
        match self.db.get_entity(entity_id).await {
            Ok(entity) => serde_json::to_string_pretty(&serde_json::json!({
                "id": entity.id,
                "name": entity.name,
                "entity_type": entity.entity_type,
                "department": entity.department,
                "clearance_level": entity.clearance_level,
                "trust_score_avg": entity.trust_score_avg,
                "session_count": entity.session_count,
                "blocked_count": entity.blocked_count,
                "quarantined": entity.quarantined != 0,
                "last_seen": entity.last_seen,
                "enrolled_at": entity.enrolled_at,
            }))
            .unwrap_or_default(),
            Err(_) => format!("Entity {} not found", entity_id),
        }
    }

    async fn query_session_details(&self, session_id: &str) -> String {
        match self.db.get_session(session_id).await {
            Ok(session) => serde_json::to_string_pretty(&serde_json::json!({
                "id": session.id,
                "source_entity_id": session.source_entity_id,
                "dest_entity_id": session.dest_entity_id,
                "intent": session.intent,
                "trust_score": session.trust_score,
                "verdict": session.verdict,
                "status": session.status,
                "started_at": session.started_at,
                "ended_at": session.ended_at,
            }))
            .unwrap_or_default(),
            Err(_) => format!("Session {} not found", session_id),
        }
    }

    async fn query_related_entities(&self, entity_id: &str, window_secs: i64) -> String {
        let since = chrono::Utc::now().timestamp() - window_secs;

        use sqlx::Row;
        
        let peers: Vec<Value> = match &self.db {
            crate::db::DbPool::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT DISTINCT dest_entity_id as peer, intent, trust_score FROM sessions WHERE source_entity_id = $1 AND started_at > $2 UNION SELECT DISTINCT source_entity_id as peer, intent, trust_score FROM sessions WHERE dest_entity_id = $3 AND started_at > $4"
                )
                .bind(entity_id).bind(since).bind(entity_id).bind(since)
                .fetch_all(pool).await.unwrap_or_default();
                
                rows.iter().map(|r| serde_json::json!({
                    "peer_entity_id": r.get::<String, _>("peer"),
                    "intent": r.get::<String, _>("intent"),
                    "trust_score": r.get::<i64, _>("trust_score"),
                })).collect()
            }
            crate::db::DbPool::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT DISTINCT dest_entity_id as peer, intent, trust_score FROM sessions WHERE source_entity_id = ? AND started_at > ? UNION SELECT DISTINCT source_entity_id as peer, intent, trust_score FROM sessions WHERE dest_entity_id = ? AND started_at > ?"
                )
                .bind(entity_id).bind(since).bind(entity_id).bind(since)
                .fetch_all(pool).await.unwrap_or_default();
                
                rows.iter().map(|r| serde_json::json!({
                    "peer_entity_id": r.get::<String, _>("peer"),
                    "intent": r.get::<String, _>("intent"),
                    "trust_score": r.get::<i64, _>("trust_score"),
                })).collect()
            }
        };

        if peers.is_empty() {
            return "No related entities found in the time window.".to_string();
        }

        serde_json::to_string_pretty(&peers).unwrap_or_default()
    }

    async fn get_network_topology(&self) -> String {
        use sqlx::Row;

        let edges: Vec<Value> = match &self.db {
            crate::db::DbPool::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT source_entity_id, dest_entity_id, intent, COUNT(*) as session_count, AVG(trust_score) as avg_trust FROM sessions WHERE started_at > $1 GROUP BY source_entity_id, dest_entity_id, intent ORDER BY session_count DESC LIMIT 50"
                )
                .bind(chrono::Utc::now().timestamp() - 86400)
                .fetch_all(pool).await.unwrap_or_default();
                
                rows.iter().map(|r| serde_json::json!({
                    "source": r.get::<String, _>("source_entity_id"),
                    "dest": r.get::<String, _>("dest_entity_id"),
                    "intent": r.get::<String, _>("intent"),
                    "sessions": r.get::<i64, _>("session_count"),
                    "avg_trust": r.get::<f64, _>("avg_trust"),
                })).collect()
            }
            crate::db::DbPool::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT source_entity_id, dest_entity_id, intent, COUNT(*) as session_count, AVG(trust_score) as avg_trust FROM sessions WHERE started_at > ? GROUP BY source_entity_id, dest_entity_id, intent ORDER BY session_count DESC LIMIT 50"
                )
                .bind(chrono::Utc::now().timestamp() - 86400)
                .fetch_all(pool).await.unwrap_or_default();
                
                rows.iter().map(|r| serde_json::json!({
                    "source": r.get::<String, _>("source_entity_id"),
                    "dest": r.get::<String, _>("dest_entity_id"),
                    "intent": r.get::<String, _>("intent"),
                    "sessions": r.get::<i64, _>("session_count"),
                    "avg_trust": r.get::<f64, _>("avg_trust"),
                })).collect()
            }
        };

        if edges.is_empty() {
            return "No active network topology data (no recent sessions).".to_string();
        }

        serde_json::to_string_pretty(&edges).unwrap_or_default()
    }

    // ─── Fallback report when agent loop exhausts steps ──────────────────────

    fn fallback_report(
        &self,
        anomaly: &Anomaly,
        steps: Vec<AgentStep>,
        actions_taken: Vec<String>,
    ) -> AgentIncidentReport {
        let mitre_ttps = mitre::map_behaviors(&format!("{:?}", anomaly.anomaly_type));

        AgentIncidentReport {
            id: uuid::Uuid::new_v4().to_string(),
            org_id: "system".to_string(),
            severity: severity_from_anomaly(&anomaly.severity),
            attack_type: format!("{:?}", anomaly.anomaly_type),
            summary: anomaly.description.clone(),
            entry_point_entity_id: Some(anomaly.entity_id.clone()),
            affected_entities: vec![anomaly.entity_id.clone()],
            timeline: vec![TimelineEvent {
                timestamp: anomaly.detected_at,
                event_type: format!("{:?}", anomaly.anomaly_type),
                entity_id: anomaly.entity_id.clone(),
                description: anomaly.description.clone(),
                severity: severity_from_anomaly(&anomaly.severity),
            }],
            mitre_ttps,
            vulnerability: None,
            data_at_risk: vec![],
            what_attacker_did: vec![anomaly.description.clone()],
            what_was_prevented: actions_taken
                .iter()
                .filter(|a| a.contains("quarantine") || a.contains("revoke"))
                .cloned()
                .collect(),
            remediation_runbook: vec![
                format!("1. Review entity {} audit log", anomaly.entity_id),
                "2. Verify entity credentials are not compromised".to_string(),
                "3. Rotate entity keypair".to_string(),
                "4. Monitor for 24 hours before releasing quarantine".to_string(),
            ],
            confidence: 0.5,
            automated_actions_taken: actions_taken,
            detected_at: anomaly.detected_at,
            investigation_steps: steps.len() as u32,
            investigation_log: steps,
        }
    }
}

fn severity_from_anomaly(sev: &AnomalySeverity) -> String {
    match sev {
        AnomalySeverity::Critical => "CRITICAL".to_string(),
        AnomalySeverity::Alert => "HIGH".to_string(),
        AnomalySeverity::Warning => "MEDIUM".to_string(),
        AnomalySeverity::Info => "LOW".to_string(),
    }
}

fn extract_json(text: &str) -> Result<String, String> {
    // Try parsing the whole thing first
    if serde_json::from_str::<Value>(text).is_ok() {
        return Ok(text.to_string());
    }

    // Find first { and last }
    let start = text.find('{').ok_or("No JSON object found")?;
    let end = text.rfind('}').ok_or("No closing brace found")?;
    if end <= start {
        return Err("Invalid JSON boundaries".to_string());
    }
    Ok(text[start..=end].to_string())
}
