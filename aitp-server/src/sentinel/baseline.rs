use crate::db::models::Session;
use crate::sentinel::Sentinel;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Behavioral baseline for a single entity — 7-day rolling window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityBaseline {
    pub entity_id: String,
    pub avg_sessions_per_hour: f64,
    pub intent_distribution: HashMap<String, u32>,
    pub avg_trust_score: f64,
    pub known_peers: HashSet<String>,
    pub avg_payload_bytes: f64,
    pub normal_hours: Vec<u8>,
    pub learning_complete: bool,
    pub sample_count: u32,
    pub last_updated: i64,
}

/// Update baselines from session history.
pub async fn update_baselines(state: &Arc<AppState>, sentinel: &Arc<Sentinel>) {
    // Only consider sessions from last 7 days
    let seven_days_ago = chrono::Utc::now().timestamp() - (7 * 24 * 3600);
    
    use sqlx::Row;
    let rows: Vec<Session> = match &state.db {
        crate::db::DbPool::Postgres(pool) => {
            sqlx::query("SELECT * FROM sessions WHERE started_at > $1")
                .bind(seven_days_ago)
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
                .bind(seven_days_ago)
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

    // Group by entity_id
    let mut grouped: HashMap<String, Vec<Session>> = HashMap::new();
    for sess in rows {
        grouped.entry(sess.source_entity_id.clone()).or_default().push(sess);
    }

    let mut baselines_lock = sentinel.baselines.write().await;
    for (entity_id, sessions) in grouped {
        let sessions: Vec<Session> = sessions;
        let session_count = sessions.len() as u32;

        let mut intent_distribution: HashMap<String, u32> = HashMap::new();
        let mut known_peers = HashSet::new();
        let mut total_trust: i64 = 0;
        let mut total_bytes: i64 = 0;
        let mut hours_seen = HashSet::new();

        let mut earliest = i64::MAX;
        let mut latest = i64::MIN;

        for sess in &sessions {
            *intent_distribution.entry(sess.intent.clone()).or_insert(0) += 1;
            known_peers.insert(sess.dest_entity_id.clone());
            total_trust += sess.trust_score;
            total_bytes += sess.bytes_tx + sess.bytes_rx;

            if sess.started_at < earliest {
                earliest = sess.started_at;
            }
            if sess.started_at > latest {
                latest = sess.started_at;
            }

            // Track active hours
            let hour = (sess.started_at % 86400) / 3600;
            hours_seen.insert(hour as u8);
        }

        let avg_trust_score = if session_count > 0 {
            total_trust as f64 / session_count as f64
        } else {
            128.0
        };

        let avg_payload_bytes = if session_count > 0 {
            total_bytes as f64 / session_count as f64
        } else {
            0.0
        };

        let mut hours_span = (chrono::Utc::now().timestamp() - earliest) as f64 / 3600.0;
        if hours_span < 0.1 {
            hours_span = 0.1;
        }
        let avg_sessions_per_hour = session_count as f64 / hours_span;

        let learning_complete = session_count >= 50;

        let mut normal_hours: Vec<u8> = hours_seen.into_iter().collect();
        normal_hours.sort();

        let baseline = EntityBaseline {
            entity_id: entity_id.clone(),
            avg_sessions_per_hour,
            intent_distribution,
            avg_trust_score,
            known_peers,
            avg_payload_bytes,
            normal_hours,
            learning_complete,
            sample_count: session_count,
            last_updated: chrono::Utc::now().timestamp(),
        };

        baselines_lock.insert(entity_id, baseline);
    }

    state
        .hub
        .log("AI", "Sentinel: behavioral baselines updated");
}
