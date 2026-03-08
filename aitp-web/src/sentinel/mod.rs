use crate::state::AppState;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Behavioral baseline per EntityID
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityBaseline {
    pub entity_id: String,
    pub session_count: u64,
    pub avg_sessions_per_hour: f64,
    pub intent_distribution: HashMap<String, u32>, // intent → count
    pub avg_trust_score: f64,
    pub known_peers: HashSet<String>,
    pub avg_payload_bytes: f64,
    pub learning_complete: bool,
    pub learning_samples: u32,
    pub last_updated: i64,
}

/// Anomaly detected by Sentinel
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    SessionFrequencySpike,    // >3x normal session rate
    NewPeer,                  // communicating with never-seen entity
    IntentDeviation,          // using intents outside normal distribution
    TrustScoreDrop,           // sudden drop in AI trust scores
    PotentialLateralMovement, // rapid expansion of peer graph
    ExfiltrationPattern,      // large outbound payload volume
    ControlSignalSpike,       // unusual ControlSignal intent usage
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Info,
    Warning,
    Alert,
    Critical,
}

pub struct Sentinel {
    pub baselines: tokio::sync::RwLock<HashMap<String, EntityBaseline>>,
    pub anomaly_log: tokio::sync::Mutex<Vec<Anomaly>>,
}

impl Sentinel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            baselines: tokio::sync::RwLock::new(HashMap::new()),
            anomaly_log: tokio::sync::Mutex::new(Vec::new()),
        })
    }
}

/// Run Sentinel in background — call from main.rs
pub async fn run(state: Arc<AppState>, sentinel: Arc<Sentinel>) {
    let mut baseline_tick = interval(Duration::from_secs(60)); // update baselines every 60s
    let mut anomaly_tick = interval(Duration::from_secs(30)); // scan for anomalies every 30s
    let mut report_tick = interval(Duration::from_secs(3600)); // hourly status report

    state.hub.log(
        "AI",
        "AITP Sentinel v0.3 starting — autonomous network defense",
    );
    state.hub.log(
        "AI",
        "Sentinel: learning mode ACTIVE — baseline collection begins",
    );

    loop {
        tokio::select! {
            _ = baseline_tick.tick() => {
                update_baselines(&state, &sentinel).await;
            }
            _ = anomaly_tick.tick() => {
                scan_anomalies(&state, &sentinel).await;
            }
            _ = report_tick.tick() => {
                generate_status_report(&state, &sentinel).await;
            }
        }
    }
}

async fn update_baselines(state: &Arc<AppState>, sentinel: &Arc<Sentinel>) {
    let pool = state.db.inner();
    let query = "
        SELECT client_entity_id, started_at, intent, trust_score, server_node_id, bytes_tx, bytes_rx
        FROM sessions
    ";

    use sqlx::Row;
    if let Ok(rows) = sqlx::query(query).fetch_all(pool).await {
        let mut grouped: HashMap<String, Vec<_>> = HashMap::new();
        for row in rows {
            let entity_id: String = row.get("client_entity_id");
            let started_at: i64 = row.get("started_at");
            let intent: String = row.get("intent");
            let trust_score: i64 = row.get("trust_score");
            let server_node_id: String = row.get("server_node_id");
            let bytes_tx: i64 = row.get("bytes_tx");
            let bytes_rx: i64 = row.get("bytes_rx");

            grouped.entry(entity_id).or_default().push((
                started_at,
                intent,
                trust_score,
                server_node_id,
                bytes_tx,
                bytes_rx,
            ));
        }

        let mut baselines_lock = sentinel.baselines.write().await;
        for (entity_id, sessions) in grouped {
            let session_count = sessions.len() as u64;

            // Computations
            let mut intent_distribution: HashMap<String, u32> = HashMap::new();
            let mut known_peers = HashSet::new();
            let mut total_trust = 0;
            let mut total_bytes = 0;

            let mut earliest = i64::MAX;
            let mut latest = i64::MIN;

            for (started_at, intent, trust_score, server_node_id, bytes_tx, bytes_rx) in &sessions {
                *intent_distribution.entry(intent.clone()).or_insert(0) += 1;
                known_peers.insert(server_node_id.clone());
                total_trust += *trust_score;
                total_bytes += *bytes_tx + *bytes_rx;

                if *started_at < earliest {
                    earliest = *started_at;
                }
                if *started_at > latest {
                    latest = *started_at;
                }
            }

            let avg_trust_score = if session_count > 0 {
                total_trust as f64 / session_count as f64
            } else {
                0.0
            };
            let avg_payload_bytes = if session_count > 0 {
                total_bytes as f64 / session_count as f64
            } else {
                0.0
            };

            let mut hours_since_first_seen = (Utc::now().timestamp() - earliest) as f64 / 3600.0;
            if hours_since_first_seen < 0.1 {
                hours_since_first_seen = 0.1;
            }
            let avg_sessions_per_hour = session_count as f64 / hours_since_first_seen;

            let learning_samples = session_count as u32;
            let learning_complete = learning_samples >= 50; // default 50

            let baseline = EntityBaseline {
                entity_id: entity_id.clone(),
                session_count,
                avg_sessions_per_hour,
                intent_distribution,
                avg_trust_score,
                known_peers,
                avg_payload_bytes,
                learning_complete,
                learning_samples,
                last_updated: Utc::now().timestamp(),
            };

            baselines_lock.insert(entity_id, baseline);
        }
    }

    state
        .hub
        .log("AI", "Sentinel: behavioral baselines updated");
}

async fn scan_anomalies(state: &Arc<AppState>, sentinel: &Arc<Sentinel>) {
    let baselines = sentinel.baselines.read().await;
    let pool = state.db.inner();

    let fifteen_mins_ago = Utc::now().timestamp() - 900;
    let query = "
        SELECT id, client_entity_id, started_at, intent, trust_score, server_node_id, bytes_tx, bytes_rx
        FROM sessions
        WHERE started_at > ?
    ";

    use sqlx::Row;
    let recent_sessions = match sqlx::query(query)
        .bind(fifteen_mins_ago)
        .fetch_all(pool)
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut recent_grouped: HashMap<String, Vec<_>> = HashMap::new();
    for row in recent_sessions {
        let entity_id: String = row.get("client_entity_id");
        recent_grouped.entry(entity_id).or_default().push(row);
    }

    for (entity_id, baseline) in baselines.iter() {
        if !baseline.learning_complete {
            continue;
        }

        let recent = recent_grouped.get(entity_id);
        let recent_count = recent.map(|v| v.len()).unwrap_or(0);
        let current_rate = recent_count as f64 * 4.0; // 15 min * 4 = per hour

        let mut anomalies_found = vec![];

        // Check 1: Session frequency spike
        if current_rate > baseline.avg_sessions_per_hour * 3.0 && current_rate > 10.0 {
            anomalies_found.push(Anomaly {
                entity_id: entity_id.clone(),
                anomaly_type: AnomalyType::SessionFrequencySpike,
                severity: AnomalySeverity::Warning,
                description: format!(
                    "Session frequency {:.1}/hr exceeds normal {:.1}/hr",
                    current_rate, baseline.avg_sessions_per_hour
                ),
                recommended_action: "Monitor".to_string(),
                confidence: 0.8,
                detected_at: Utc::now().timestamp(),
            });
        }

        if let Some(recent_list) = recent {
            let mut recent_control_signal = 0;
            let mut new_peers_last_hour = 0;
            let mut recent_trust_total = 0;

            for row in recent_list {
                let intent: String = row.get("intent");
                let server_node_id: String = row.get("server_node_id");
                let trust_score: i64 = row.get("trust_score");

                if intent == "ControlSignal" {
                    recent_control_signal += 1;
                }
                if !baseline.known_peers.contains(&server_node_id) {
                    new_peers_last_hour += 1;

                    // Check 3: New peer detection
                    anomalies_found.push(Anomaly {
                        entity_id: entity_id.clone(),
                        anomaly_type: AnomalyType::NewPeer,
                        severity: AnomalySeverity::Warning,
                        description: format!("Communicating with unknown peer {}", server_node_id),
                        recommended_action: "Verify peer identity".to_string(),
                        confidence: 0.9,
                        detected_at: Utc::now().timestamp(),
                    });
                }
                recent_trust_total += trust_score;
            }

            // Check 2: ControlSignal spike
            let baseline_control = baseline
                .intent_distribution
                .get("ControlSignal")
                .unwrap_or(&0);
            if recent_control_signal as u32 > *baseline_control * 2 && recent_control_signal > 5 {
                anomalies_found.push(Anomaly {
                    entity_id: entity_id.clone(),
                    anomaly_type: AnomalyType::ControlSignalSpike,
                    severity: AnomalySeverity::Critical,
                    description: format!(
                        "ControlSignal count {} more than 2x baseline",
                        recent_control_signal
                    ),
                    recommended_action: "Revoke sessions immediately".to_string(),
                    confidence: 0.95,
                    detected_at: Utc::now().timestamp(),
                });
            }

            // Check 4: Trust score drop
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
                    detected_at: Utc::now().timestamp(),
                });
            }

            // Check 5: Lateral movement
            if new_peers_last_hour > 5 {
                anomalies_found.push(Anomaly {
                    entity_id: entity_id.clone(),
                    anomaly_type: AnomalyType::PotentialLateralMovement,
                    severity: AnomalySeverity::Critical,
                    description: format!(
                        "{} new peers detected in 15m window",
                        new_peers_last_hour
                    ),
                    recommended_action: "Isolate entity".to_string(),
                    confidence: 0.95,
                    detected_at: Utc::now().timestamp(),
                });
            }
        }

        if !anomalies_found.is_empty() {
            let mut log = sentinel.anomaly_log.lock().await;

            for anomaly in anomalies_found {
                crate::metrics::METRIC_ANOMALIES_DETECTED.inc();
                let audit_severity = match anomaly.severity {
                    AnomalySeverity::Info => "info",
                    AnomalySeverity::Warning => "warning",
                    AnomalySeverity::Alert => "warning",
                    AnomalySeverity::Critical => "critical",
                };

                let _ = sqlx::query("
                    INSERT INTO audit_events (id, event_type, severity, entity_id, description, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ")
                .bind(uuid::Uuid::new_v4().to_string())
                .bind("SentinelAnomaly")
                .bind(audit_severity)
                .bind(&anomaly.entity_id)
                .bind(&anomaly.description)
                .bind(Utc::now().timestamp())
                .execute(pool)
                .await;

                state.hub.alert(
                    &format!("{:?}", anomaly.anomaly_type),
                    audit_severity,
                    &anomaly.entity_id,
                    &anomaly.description,
                );

                // Add to log
                log.push(anomaly);
            }
        }
    }
}

#[derive(Serialize)]
struct SentinelReport {
    timestamp: i64,
    active_entities: usize,
    anomalies: Vec<Anomaly>,
    recommendations: Vec<String>,
}

async fn generate_status_report(state: &Arc<AppState>, sentinel: &Arc<Sentinel>) {
    let anomalies = sentinel.anomaly_log.lock().await;
    let critical = anomalies
        .iter()
        .filter(|a| matches!(a.severity, AnomalySeverity::Critical))
        .count();
    let alerts = anomalies
        .iter()
        .filter(|a| matches!(a.severity, AnomalySeverity::Alert))
        .count();

    let entities = sentinel.baselines.read().await.len();

    state.hub.log(
        "AI",
        &format!(
            "Sentinel hourly report: {} critical  {} alerts  {} entities monitored",
            critical, alerts, entities
        ),
    );

    // Also write JSON report to ./reports/sentinel_YYYYMMDD_HH.json
    let now = chrono::Local::now();
    let filename = format!("./reports/sentinel_{}.json", now.format("%Y%m%d_%H"));

    if let Err(e) = tokio::fs::create_dir_all("./reports").await {
        tracing::error!("Failed to create reports directory: {}", e);
        return;
    }

    let report = SentinelReport {
        timestamp: Utc::now().timestamp(),
        active_entities: entities,
        anomalies: anomalies.clone(),
        recommendations: vec!["Review critical alerts immediately".to_string()],
    };

    if let Ok(json) = serde_json::to_string_pretty(&report) {
        let _ = tokio::fs::write(&filename, json).await;
    }
}
