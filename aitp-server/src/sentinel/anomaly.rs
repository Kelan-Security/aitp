use crate::db::models::{Session, WsEvent};
use crate::sentinel::Sentinel;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ────────────────────────── Anomaly Types ──────────────────────────

/// All 7 anomaly detection classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    SessionFrequencySpike,
    NewPeer,
    IntentDeviation,
    TrustScoreDrop,
    LateralMovement,
    ExfiltrationPattern,
    ControlSignalSpike,
}

impl AnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyType::SessionFrequencySpike => "SessionFrequencySpike",
            AnomalyType::NewPeer => "NewPeer",
            AnomalyType::IntentDeviation => "IntentDeviation",
            AnomalyType::TrustScoreDrop => "TrustScoreDrop",
            AnomalyType::LateralMovement => "LateralMovement",
            AnomalyType::ExfiltrationPattern => "ExfiltrationPattern",
            AnomalyType::ControlSignalSpike => "ControlSignalSpike",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Info,
    Warning,
    Alert,
    Critical,
}

impl AnomalySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalySeverity::Info => "info",
            AnomalySeverity::Warning => "warning",
            AnomalySeverity::Alert => "alert",
            AnomalySeverity::Critical => "critical",
        }
    }
}

/// A detected anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub entity_id: String,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub recommended_action: String,
    pub confidence: f32,
    pub detected_at: i64,
}

// ────────────────────────── Anomaly Scanning ──────────────────────────

/// Scan for anomalies across all entities with learned baselines.
pub async fn scan_anomalies(state: &Arc<AppState>, sentinel: &Arc<Sentinel>) {
    let _baselines = sentinel.baselines.read().await;
    let fifteen_mins_ago = chrono::Utc::now().timestamp() - 900;
    
    use sqlx::Row;
    let recent_sessions: Vec<Session> = match &state.db {
        crate::db::DbPool::Postgres(pool) => {
            sqlx::query("SELECT * FROM sessions WHERE started_at > $1")
                .bind(fifteen_mins_ago)
                .fetch_all(pool)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| Session {
                    id: r.get("id"),
                    org_id: r.get("org_id"),
                    source_entity_id: r.get("source_entity_id"),
                    dest_entity_id: r.get("dest_entity_id"),
                    intent: r.get("intent"),
                    trust_score: r.get("trust_score"),
                    verdict: r.get("verdict"),
                    ai_reasoning: r.get("ai_reasoning"),
                    ai_latency_ms: r.get("ai_latency_ms"),
                    status: r.get("status"),
                    bytes_tx: r.get("bytes_tx"),
                    bytes_rx: r.get("bytes_rx"),
                    anomaly_flags: r.get("anomaly_flags"),
                    started_at: r.get("started_at"),
                    ended_at: r.get("ended_at"),
                    close_reason: r.get("close_reason"),
                })
                .collect()
        }
        crate::db::DbPool::Sqlite(pool) => {
            sqlx::query("SELECT * FROM sessions WHERE started_at > ?")
                .bind(fifteen_mins_ago)
                .fetch_all(pool)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| Session {
                    id: r.get("id"),
                    org_id: r.get("org_id"),
                    source_entity_id: r.get("source_entity_id"),
                    dest_entity_id: r.get("dest_entity_id"),
                    intent: r.get("intent"),
                    trust_score: r.get("trust_score"),
                    verdict: r.get("verdict"),
                    ai_reasoning: r.get("ai_reasoning"),
                    ai_latency_ms: r.get("ai_latency_ms"),
                    status: r.get("status"),
                    bytes_tx: r.get("bytes_tx"),
                    bytes_rx: r.get("bytes_rx"),
                    anomaly_flags: r.get("anomaly_flags"),
                    started_at: r.get("started_at"),
                    ended_at: r.get("ended_at"),
                    close_reason: r.get("close_reason"),
                })
                .collect()
        }
    };

    // Group recent sessions by entity
    let mut recent_grouped: HashMap<String, Vec<Session>> = HashMap::new();
    for sess in recent_sessions {
        recent_grouped.entry(sess.source_entity_id.clone()).or_default().push(sess);
    }

    // Only scan entities that are marked dirty (had activity)
    let dirty_list: Vec<String> = sentinel.dirty_entities.iter()
        .filter(|e| e.value().elapsed() < std::time::Duration::from_secs(30))
        .map(|e| e.key().clone())
        .collect();

    for entity_id in dirty_list {
        let baseline_map = sentinel.baselines.read().await;
        let baseline = match baseline_map.get(&entity_id) {
            Some(b) => b,
            None => {
                sentinel.dirty_entities.remove(&entity_id);
                continue;
            }
        };
        if !baseline.learning_complete {
            continue;
        }

        let recent = recent_grouped.get(&entity_id);
        let recent_count = recent.map(|v| v.len()).unwrap_or(0);
        let current_rate = recent_count as f64 * 4.0; // 15 min × 4 = per hour

        let mut anomalies_found = vec![];

        // ── Check 1: Session frequency spike ──
        if current_rate > baseline.avg_sessions_per_hour * 3.0 && current_rate > 10.0 {
            anomalies_found.push(Anomaly {
                entity_id: entity_id.clone(),
                anomaly_type: AnomalyType::SessionFrequencySpike,
                severity: AnomalySeverity::Warning,
                description: format!(
                    "Session frequency {:.1}/hr exceeds 3× baseline {:.1}/hr",
                    current_rate, baseline.avg_sessions_per_hour
                ),
                recommended_action: "Monitor".to_string(),
                confidence: 0.8,
                detected_at: chrono::Utc::now().timestamp(),
            });
        }

        if let Some(recent_list) = recent {
            let recent_list: &Vec<Session> = recent_list;
            let mut recent_control_signal = 0u32;
            let mut new_peers_last_hour = 0u32;
            let mut recent_trust_total: i64 = 0;
            let mut total_bytes_tx: i64 = 0;
            let mut intent_counts: HashMap<String, u32> = HashMap::new();

            for sess in recent_list {
                let intent = &sess.intent;
                let dest_entity_id = &sess.dest_entity_id;
                let trust_score = sess.trust_score;
                let bytes_tx = sess.bytes_tx;

                *intent_counts.entry(intent.clone()).or_insert(0) += 1;

                if intent == "ControlSignal" {
                    recent_control_signal += 1;
                }

                // ── Check 2: New peer ──
                if !baseline.known_peers.contains(dest_entity_id.as_str()) {
                    new_peers_last_hour += 1;
                    anomalies_found.push(Anomaly {
                        entity_id: entity_id.clone(),
                        anomaly_type: AnomalyType::NewPeer,
                        severity: AnomalySeverity::Warning,
                        description: format!(
                            "Communicating with unknown peer {}",
                            &dest_entity_id[..16.min(dest_entity_id.len())]
                        ),
                        recommended_action: "Verify peer identity".to_string(),
                        confidence: 0.9,
                        detected_at: chrono::Utc::now().timestamp(),
                    });
                }

                recent_trust_total += trust_score;
                total_bytes_tx += bytes_tx;
            }

            // ── Check 3: Intent deviation ──
            for (intent, count) in &intent_counts {
                let baseline_count = baseline.intent_distribution.get(intent).unwrap_or(&0);
                let baseline_total: u32 = baseline.intent_distribution.values().sum();
                if baseline_total > 0 {
                    let baseline_pct = *baseline_count as f64 / baseline_total as f64;
                    let current_pct = *count as f64 / recent_list.len() as f64;
                    if current_pct > baseline_pct * 3.0 && baseline_pct < 0.1 && *count > 3 {
                        anomalies_found.push(Anomaly {
                            entity_id: entity_id.clone(),
                            anomaly_type: AnomalyType::IntentDeviation,
                            severity: AnomalySeverity::Alert,
                            description: format!(
                                "Intent {} usage {:.0}% vs baseline {:.0}%",
                                intent,
                                current_pct * 100.0,
                                baseline_pct * 100.0
                            ),
                            recommended_action: "Investigate intent usage".to_string(),
                            confidence: 0.85,
                            detected_at: chrono::Utc::now().timestamp(),
                        });
                    }
                }
            }

            // ── Check 4: Trust score drop ──
            let recent_avg_trust = if !recent_list.is_empty() {
                recent_trust_total as f64 / recent_list.len() as f64
            } else {
                baseline.avg_trust_score
            };

            if recent_avg_trust < baseline.avg_trust_score - 40.0 {
                anomalies_found.push(Anomaly {
                    entity_id: entity_id.clone(),
                    anomaly_type: AnomalyType::TrustScoreDrop,
                    severity: AnomalySeverity::Alert,
                    description: format!(
                        "Trust dropped to {:.1} (baseline {:.1})",
                        recent_avg_trust, baseline.avg_trust_score
                    ),
                    recommended_action: "Investigate interactions".to_string(),
                    confidence: 0.9,
                    detected_at: chrono::Utc::now().timestamp(),
                });
            }

            // ── Check 5: Lateral movement ──
            if new_peers_last_hour > 3 {
                anomalies_found.push(Anomaly {
                    entity_id: entity_id.clone(),
                    anomaly_type: AnomalyType::LateralMovement,
                    severity: AnomalySeverity::Critical,
                    description: format!(
                        "{} new peers detected in 15m window — potential lateral movement",
                        new_peers_last_hour
                    ),
                    recommended_action: "Isolate entity immediately".to_string(),
                    confidence: 0.95,
                    detected_at: chrono::Utc::now().timestamp(),
                });
            }

            // ── Check 6: Exfiltration pattern ──
            let avg_recent_bytes = if !recent_list.is_empty() {
                total_bytes_tx as f64 / recent_list.len() as f64
            } else {
                0.0
            };
            if avg_recent_bytes > baseline.avg_payload_bytes * 5.0
                && baseline.avg_payload_bytes > 100.0
            {
                anomalies_found.push(Anomaly {
                    entity_id: entity_id.clone(),
                    anomaly_type: AnomalyType::ExfiltrationPattern,
                    severity: AnomalySeverity::Critical,
                    description: format!(
                        "Outbound bytes {:.0} exceed 5× baseline {:.0}",
                        avg_recent_bytes, baseline.avg_payload_bytes
                    ),
                    recommended_action: "Quarantine and investigate".to_string(),
                    confidence: 0.9,
                    detected_at: chrono::Utc::now().timestamp(),
                });
            }

            // ── Check 7: ControlSignal spike ──
            let baseline_control = baseline
                .intent_distribution
                .get("ControlSignal")
                .unwrap_or(&0);
            if recent_control_signal > *baseline_control * 2 && recent_control_signal > 5 {
                anomalies_found.push(Anomaly {
                    entity_id: entity_id.clone(),
                    anomaly_type: AnomalyType::ControlSignalSpike,
                    severity: AnomalySeverity::Critical,
                    description: format!(
                        "ControlSignal count {} more than 2× baseline {}",
                        recent_control_signal, baseline_control
                    ),
                    recommended_action: "Revoke sessions immediately".to_string(),
                    confidence: 0.95,
                    detected_at: chrono::Utc::now().timestamp(),
                });
            }
        }

        // Store anomalies
        if !anomalies_found.is_empty() {
            let mut log = sentinel.anomalies.lock().await;

            for anomaly in anomalies_found {
                // Broadcast via WebSocket
                state.hub.broadcast(WsEvent::AnomalyDetected {
                    entity_id: anomaly.entity_id.clone(),
                    anomaly_type: anomaly.anomaly_type.as_str().to_string(),
                    severity: anomaly.severity.as_str().to_string(),
                    description: anomaly.description.clone(),
                    confidence: anomaly.confidence,
                    ts: anomaly.detected_at,
                });

                // Write to audit chain
                let sql_pg = "INSERT INTO audit_chain (id, org_id, event_type, severity, source_entity_id, description, metadata, prev_hash, entry_hash, created_at) VALUES ($1, 'system', 'SentinelAnomaly', $2, $3, $4, '{}', '', '', $5)";
                let sql_sq = "INSERT INTO audit_chain (id, org_id, event_type, severity, source_entity_id, description, metadata, prev_hash, entry_hash, created_at) VALUES (?, 'system', 'SentinelAnomaly', ?, ?, ?, '{}', '', '', ?)";
                let new_audit_id = uuid::Uuid::new_v4().to_string();
                
                match &state.db {
                    crate::db::DbPool::Postgres(pool) => {
                        let _ = sqlx::query(sql_pg)
                            .bind(&new_audit_id)
                            .bind(anomaly.severity.as_str())
                            .bind(&anomaly.entity_id)
                            .bind(&anomaly.description)
                            .bind(anomaly.detected_at)
                            .execute(pool)
                            .await;
                    }
                    crate::db::DbPool::Sqlite(pool) => {
                        let _ = sqlx::query(sql_sq)
                            .bind(&new_audit_id)
                            .bind(anomaly.severity.as_str())
                            .bind(&anomaly.entity_id)
                            .bind(&anomaly.description)
                            .bind(anomaly.detected_at)
                            .execute(pool)
                            .await;
                    }
                }

                // Ring buffer — keep last 1000
                if log.len() >= 1000 {
                    log.pop_front();
                }
                log.push_back(anomaly);
            }
        }
        
        // Remove from dirty list after scan
        sentinel.dirty_entities.remove(&entity_id);
    }
}

/// Check for critical anomalies and trigger threat response.
pub async fn check_critical_anomalies(state: &Arc<AppState>, sentinel: &Arc<Sentinel>) {
    if !state.config.auto_quarantine {
        return;
    }

    let anomalies = sentinel.anomalies.lock().await;
    let critical: Vec<Anomaly> = anomalies
        .iter()
        .filter(|a| matches!(a.severity, AnomalySeverity::Critical))
        .filter(|a| a.detected_at > chrono::Utc::now().timestamp() - 10) // last 10 seconds
        .cloned()
        .collect();

    drop(anomalies); // Release lock before async work

    for anomaly in critical {
        // Use the Gemini-powered agentic threat response engine.
        // Falls back to rule-based response if no API key is configured.
        crate::agent::activate_agent(state, &anomaly).await;
    }
}
