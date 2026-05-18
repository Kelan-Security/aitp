pub mod anomaly;
pub mod baseline;
pub mod threat;

use crate::state::AppState;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

pub use anomaly::{Anomaly, AnomalySeverity, AnomalyType};
pub use baseline::{EntityBaseline, SentinelState};
pub use threat::SecurityIncident;

use crate::db;
use crate::db::models::WsEvent;

// ── NEW EVENT TYPES ──────────────────────────────────────────────────────────

/// Published by the trust engine after every session evaluation.
/// Sent to the Sentinel via a non-blocking mpsc channel.
/// Dropping an event (full channel) is acceptable — we have a fallback timer.
#[derive(Debug, Clone)]
pub struct SentinelEvent {
    /// Entity that initiated the session
    pub entity_id: String,
    pub org_id: String,

    /// The session that was evaluated
    pub session_id: String,
    pub dest_entity_id: String,
    pub intent: String,
    pub trust_score: u8,
    pub verdict: String, // "Allow" | "Monitor" | "Deny"
    pub bytes_tx: u64,

    /// Timestamp (Unix seconds)
    pub occurred_at: i64,

    /// Pre-classified signal strength — tells Sentinel how urgent this is
    pub signal: SentinelSignal,
}

/// How urgently the Sentinel should evaluate this event.
#[derive(Debug, Clone, PartialEq)]
pub enum SentinelSignal {
    /// Normal activity — update baseline stats, no immediate anomaly check
    Routine,

    /// Potentially interesting — check against baseline within 1 second
    Elevated,

    /// High-confidence anomaly indicator — check immediately, < 5ms
    /// Examples: new destination peer, ControlSignal from unexpected source,
    /// trust score drop > 40 points below baseline
    Critical,
}

impl SentinelEvent {
    /// Classify signal strength based on session properties.
    /// Called by the trust engine before publishing the event.
    pub fn classify(
        intent: &str,
        trust_score: u8,
        baseline_score: f64,
        is_new_peer: bool,
        verdict: &str,
    ) -> SentinelSignal {
        // Immediate critical signals — these bypass all timers
        if is_new_peer {
            return SentinelSignal::Critical;
        }
        if intent == "ControlSignal" {
            return SentinelSignal::Critical;
        }
        if verdict == "Deny" {
            return SentinelSignal::Critical;
        }
        if (trust_score as f64) < baseline_score - 40.0 {
            return SentinelSignal::Critical;
        }

        // Elevated signals — check within 1 second
        if intent == "FileTransfer" {
            return SentinelSignal::Elevated;
        }
        if intent == "AgentCoordinate" {
            return SentinelSignal::Elevated;
        }
        if (trust_score as f64) < baseline_score - 20.0 {
            return SentinelSignal::Elevated;
        }

        // Everything else is routine baseline maintenance
        SentinelSignal::Routine
    }
}

// ── REFACTORED MAIN LOOP ─────────────────────────────────────────────────────

/// Main Sentinel task — runs forever as a background tokio task.
/// Receives session events via channel, processes them immediately
/// (for Critical signals) or batches them (for Routine signals).
pub async fn run_event_driven(state: Arc<AppState>, mut rx: mpsc::Receiver<SentinelEvent>) {
    tracing::info!("Sentinel v0.4 starting — event-driven mode");
    tracing::info!("Critical anomaly detection latency: < 5ms");
    tracing::info!("Background baseline update interval: 60s");

    // Deferred buffer for Routine/Elevated events
    // Processed in batches to avoid DB hammering
    let mut deferred_buffer: VecDeque<SentinelEvent> = VecDeque::with_capacity(1000);

    // Background timers
    let mut baseline_tick = interval(Duration::from_secs(60)); // update baselines
    let mut deferred_tick = interval(Duration::from_secs(5)); // flush deferred buffer
    let mut expiry_tick = interval(Duration::from_secs(300)); // clean up old data

    loop {
        tokio::select! {
            // ── HIGHEST PRIORITY: process incoming events
            Some(event) = rx.recv() => {
                match event.signal {
                    SentinelSignal::Critical => {
                        // Process immediately — this is the < 5ms path
                        // No batching, no waiting
                        process_critical_event(&state, &event).await;
                    }
                    SentinelSignal::Elevated | SentinelSignal::Routine => {
                        // Buffer for batch processing
                        deferred_buffer.push_back(event);
                        // Cap buffer size — drop oldest if overwhelmed
                        if deferred_buffer.len() > 5000 {
                            deferred_buffer.pop_front();
                        }
                    }
                }
            }

            // ── Flush deferred buffer every 5 seconds
            _ = deferred_tick.tick() => {
                // Update channel depth metric (approximated by deferred buffer size)
                crate::metrics::SENTINEL_CHANNEL_DEPTH
                    .set(deferred_buffer.len() as f64);

                if !deferred_buffer.is_empty() {
                    let batch: Vec<SentinelEvent> = deferred_buffer.drain(..).collect();
                    process_deferred_batch(&state, batch).await;
                }
            }

            // ── Update behavioral baselines every 60 seconds
            _ = baseline_tick.tick() => {
                update_all_baselines(&state).await;
            }

            // ── Expire old anomalies and sessions every 5 minutes
            _ = expiry_tick.tick() => {
                cleanup_expired_data(&state).await;
            }
        }
    }
}

async fn process_critical_event(state: &Arc<AppState>, event: &SentinelEvent) {
    let start = std::time::Instant::now();

    let baseline = match state.sentinel.get_baseline(&event.org_id, &event.entity_id).await {
        Some(b) => b,
        None => {
            check_without_baseline(state, event).await;
            return;
        }
    };

    let anomalies = detect_targeted_anomalies(state, event, &baseline).await;

    let elapsed = start.elapsed();
    let latency_ms = elapsed.as_secs_f64() * 1000.0;
    tracing::debug!(
        entity_id = %&event.entity_id[..8],
        latency_us = elapsed.as_micros(),
        anomalies_found = anomalies.len(),
        "critical event processed"
    );

    // Record critical-path detection latency
    crate::metrics::ANOMALY_DETECTION_LATENCY
        .with_label_values(&["critical"])
        .observe(latency_ms);

    for anomaly in anomalies {
        handle_anomaly(state, anomaly, event).await;
    }

    state.sentinel.touch_baseline(&event.org_id, &event.entity_id, event).await;
}

async fn detect_targeted_anomalies(
    state: &Arc<AppState>,
    event: &SentinelEvent,
    baseline: &EntityBaseline,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();
    let now = chrono::Utc::now().timestamp();

    if event.signal == SentinelSignal::Critical
        && !baseline.known_peers.contains(&event.dest_entity_id)
    {
        anomalies.push(Anomaly {
            entity_id: event.entity_id.clone(),
            org_id: event.org_id.clone(),
            anomaly_type: AnomalyType::NewPeer,
            severity: AnomalySeverity::Critical,
            description: format!(
                "Entity {} communicated with new peer {} — \
                 not seen in {} previous sessions",
                &event.entity_id[..8],
                &event.dest_entity_id[..8],
                baseline.sample_count
            ),
            confidence: 0.92,
            session_id: Some(event.session_id.clone()),
            detected_at: now,
            metadata: serde_json::json!({
                "new_peer":     event.dest_entity_id,
                "intent":       event.intent,
                "trust_score":  event.trust_score,
                "sample_count": baseline.sample_count,
            }),
            recommended_action: "Investigate peer identity".to_string(),
        });
    }

    if (event.trust_score as f64) < baseline.avg_trust_score - 40.0 && baseline.sample_count > 20 {
        let drop = baseline.avg_trust_score - event.trust_score as f64;
        anomalies.push(Anomaly {
            entity_id: event.entity_id.clone(),
            org_id: event.org_id.clone(),
            anomaly_type: AnomalyType::TrustScoreDrop,
            severity: if drop > 60.0 {
                AnomalySeverity::Critical
            } else {
                AnomalySeverity::Alert
            },
            description: format!(
                "Trust score dropped {:.0} points below baseline \
                 (current: {}, baseline: {:.0})",
                drop, event.trust_score, baseline.avg_trust_score
            ),
            confidence: (drop / 100.0).min(0.99) as f32,
            session_id: Some(event.session_id.clone()),
            detected_at: now,
            metadata: serde_json::json!({
                "current_score":  event.trust_score,
                "baseline_score": baseline.avg_trust_score,
                "drop":           drop,
                "verdict":        event.verdict,
            }),
            recommended_action: "Monitor entity interactions".to_string(),
        });
    }

    if event.intent == "ControlSignal" {
        let cs_fraction = baseline
            .intent_distribution
            .get("ControlSignal")
            .copied()
            .unwrap_or(0.0);

        if cs_fraction < 0.05 && baseline.sample_count > 10 {
            anomalies.push(Anomaly {
                entity_id: event.entity_id.clone(),
                org_id: event.org_id.clone(),
                anomaly_type: AnomalyType::IntentDeviation,
                severity: AnomalySeverity::Critical,
                description: format!(
                    "ControlSignal intent from entity that uses it in \
                     only {:.1}% of sessions (current session flagged)",
                    cs_fraction * 100.0
                ),
                confidence: 0.88,
                session_id: Some(event.session_id.clone()),
                detected_at: now,
                metadata: serde_json::json!({
                    "intent":            event.intent,
                    "historical_fraction": cs_fraction,
                    "trust_score":       event.trust_score,
                }),
                recommended_action: "Verify process integrity".to_string(),
            });
        }
    }

    if event.verdict == "Deny" {
        let recent_denials = state.sentinel.count_recent_denials(&event.org_id, &event.entity_id, 60);

        if recent_denials >= 3 {
            anomalies.push(Anomaly {
                entity_id: event.entity_id.clone(),
                org_id: event.org_id.clone(),
                anomaly_type: AnomalyType::SessionFrequencySpike,
                severity: AnomalySeverity::Alert,
                description: format!(
                    "{} denied sessions in last 60 seconds for entity {}",
                    recent_denials,
                    &event.entity_id[..8]
                ),
                confidence: 0.85,
                session_id: Some(event.session_id.clone()),
                detected_at: now,
                metadata: serde_json::json!({
                    "recent_denials":  recent_denials,
                    "window_seconds":  60,
                }),
                recommended_action: "Check for brute force or misconfiguration".to_string(),
            });
        }
    }

    anomalies
}

async fn check_without_baseline(state: &Arc<AppState>, event: &SentinelEvent) {
    if event.intent == "ControlSignal" && event.trust_score < 100 {
        let anomaly = Anomaly {
            entity_id: event.entity_id.clone(),
            org_id: event.org_id.clone(),
            anomaly_type: AnomalyType::IntentDeviation,
            severity: AnomalySeverity::Alert,
            description: format!(
                "ControlSignal from entity with no baseline history (score: {})",
                event.trust_score
            ),
            confidence: 0.70,
            session_id: Some(event.session_id.clone()),
            detected_at: chrono::Utc::now().timestamp(),
            metadata: serde_json::json!({ "intent": event.intent.clone() }),
            recommended_action: "Monitor new entity behavior".to_string(),
        };
        handle_anomaly(state, anomaly, event).await;
    }
}

async fn handle_anomaly(state: &Arc<AppState>, anomaly: Anomaly, _event: &SentinelEvent) {
    tracing::warn!(
        entity_id  = %&anomaly.entity_id[..8],
        anomaly    = ?anomaly.anomaly_type,
        severity   = ?anomaly.severity,
        confidence = anomaly.confidence,
        "Sentinel anomaly detected"
    );

    // Record anomaly metric
    crate::metrics::ANOMALIES_DETECTED
        .with_label_values(&[
            anomaly.anomaly_type.as_str(),
            anomaly.severity.as_str(),
            &anomaly.org_id,
        ])
        .inc();

    state.hub.broadcast(&anomaly.org_id, WsEvent::AnomalyDetected {
        entity_id: anomaly.entity_id.clone(),
        anomaly_type: anomaly.anomaly_type.as_str().to_string(),
        severity: anomaly.severity.as_str().to_string(),
        description: anomaly.description.clone(),
        confidence: anomaly.confidence,
        ts: anomaly.detected_at,
    });

    if matches!(anomaly.severity, AnomalySeverity::Critical)
        && anomaly.confidence > 0.85
        && state.config.auto_quarantine
    {
        tracing::warn!(
            entity_id = %&anomaly.entity_id[..8],
            "Auto-quarantining entity due to Critical anomaly"
        );

        if let Ok(prefix) = parse_entity_prefix(&anomaly.entity_id) {
            let revoked: u32 = state.enforcer.revoke_entity(&prefix).await.unwrap_or(0);
            tracing::warn!(sessions_revoked = revoked, "XDP permits revoked");
        }

        let _ = db::quarantine_entity(&state.db, &anomaly.entity_id).await;

        // Increment quarantined entities gauge
        crate::metrics::QUARANTINED_ENTITIES.inc();

        state.hub.broadcast(&anomaly.org_id, WsEvent::EntityQuarantined {
            entity_id: anomaly.entity_id.clone(),
            reason: anomaly.description.clone(),
            active_sessions_killed: 0,
            ts: anomaly.detected_at,
        });

        // Activate Threat Response Agent asynchronously (expensive, don't block)
        let state_clone = Arc::clone(state);
        let anomaly_clone = anomaly.clone();
        tokio::spawn(async move {
            crate::agent::activate_agent(&state_clone, &anomaly_clone).await;
        });
    }

    let _ = state
        .db
        .create_anomaly(
            anomaly.entity_id.clone(),
            anomaly.org_id.clone(),
            format!("{:?}", anomaly.anomaly_type),
            anomaly.severity.as_str().to_string(),
            anomaly.description.clone(),
            anomaly.confidence,
            anomaly.session_id.clone(),
            serde_json::to_string(&anomaly.metadata).unwrap_or_default(),
        )
        .await;
}

async fn process_deferred_batch(state: &Arc<AppState>, events: Vec<SentinelEvent>) {
    let mut entity_events: std::collections::HashMap<(String, String), Vec<&SentinelEvent>> =
        std::collections::HashMap::new();

    for event in &events {
        entity_events
            .entry((event.org_id.clone(), event.entity_id.clone()))
            .or_default()
            .push(event);
    }

    for ((org_id, entity_id), entity_batch) in &entity_events {
        update_entity_baseline(state, org_id, entity_id, entity_batch).await;
        check_slow_anomalies(state, org_id, entity_id, entity_batch).await;
    }
}

async fn update_entity_baseline(state: &Arc<AppState>, org_id: &str, entity_id: &str, events: &[&SentinelEvent]) {
    let mut baseline = state.sentinel.get_or_create_baseline(org_id, entity_id).await;

    for event in events {
        let n = baseline.sample_count as f64;
        baseline.avg_trust_score =
            (baseline.avg_trust_score * n + event.trust_score as f64) / (n + 1.0);

        *baseline
            .intent_distribution
            .entry(event.intent.clone())
            .or_insert(0.0) += 1.0 / (n + 1.0);

        if !baseline.known_peers.contains(&event.dest_entity_id) {
            baseline.known_peers.push(event.dest_entity_id.clone());
        }

        baseline.sample_count += 1;
    }

    state.sentinel.mark_baseline_dirty(org_id, entity_id).await;
}

async fn check_slow_anomalies(state: &Arc<AppState>, org_id: &str, entity_id: &str, events: &[&SentinelEvent]) {
    let baseline = match state.sentinel.get_baseline(org_id, entity_id).await {
        Some(b) => b,
        None => return,
    };

    for event in events.iter().filter(|e| e.intent == "FileTransfer") {
        if event.bytes_tx > (baseline.avg_payload_bytes * 5.0) as u64
            && baseline.avg_payload_bytes > 0.0
            && baseline.sample_count > 20
        {
            let anomaly = Anomaly {
                entity_id: entity_id.to_string(),
                org_id: event.org_id.clone(),
                anomaly_type: AnomalyType::ExfiltrationPattern,
                severity: AnomalySeverity::Alert,
                description: format!(
                    "FileTransfer volume {}x above baseline ({} vs {:.0} avg)",
                    event.bytes_tx / baseline.avg_payload_bytes.max(1.0) as u64,
                    event.bytes_tx,
                    baseline.avg_payload_bytes
                ),
                confidence: 0.78,
                session_id: Some(event.session_id.clone()),
                detected_at: chrono::Utc::now().timestamp(),
                metadata: serde_json::json!({
                    "bytes_tx":  event.bytes_tx,
                    "avg_bytes": baseline.avg_payload_bytes,
                }),
                recommended_action: "Quarantine and investigate data transfer".to_string(),
            };
            handle_anomaly(state, anomaly, event).await;
        }
    }
}

async fn update_all_baselines(state: &Arc<AppState>) {
    let dirty_keys = state.sentinel.take_dirty_baselines().await;
    if dirty_keys.is_empty() {
        return;
    }

    tracing::debug!("Flushing {} baseline(s) to DB", dirty_keys.len());

    for (org_id, entity_id) in dirty_keys {
        if let Some(baseline) = state.sentinel.get_baseline(&org_id, &entity_id).await {
            let _ = db::upsert_baseline(&state.db, &org_id, &entity_id, &baseline).await;
        }
    }
}

async fn cleanup_expired_data(state: &Arc<AppState>) {
    let cutoff = chrono::Utc::now().timestamp() - 90 * 86400; // 90 days
    let _ = db::delete_old_anomalies(&state.db, cutoff).await;
}

fn parse_entity_prefix(entity_id: &str) -> anyhow::Result<[u8; 8]> {
    let bytes = hex::decode(&entity_id[..16.min(entity_id.len())])?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad prefix"))
}
