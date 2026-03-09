use crate::state::AppState;
use super::Sentinel;
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
    let pool = state.db.inner();

    // Only consider sessions from last 7 days
    let seven_days_ago = chrono::Utc::now().timestamp() - (7 * 24 * 3600);

    let query = "
        SELECT source_entity_id, started_at, intent, trust_score, dest_entity_id, bytes_tx, bytes_rx
        FROM sessions
        WHERE started_at > ?
    ";

    use sqlx::Row;
    let rows = match sqlx::query(query)
        .bind(seven_days_ago)
        .fetch_all(pool)
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut grouped: HashMap<String, Vec<(i64, String, i64, String, i64, i64)>> = HashMap::new();
    for row in &rows {
        let entity_id: String = row.get("source_entity_id");
        let started_at: i64 = row.get("started_at");
        let intent: String = row.get("intent");
        let trust_score: i64 = row.get("trust_score");
        let dest_id: String = row.get("dest_entity_id");
        let bytes_tx: i64 = row.get("bytes_tx");
        let bytes_rx: i64 = row.get("bytes_rx");

        grouped
            .entry(entity_id)
            .or_default()
            .push((started_at, intent, trust_score, dest_id, bytes_tx, bytes_rx));
    }

    let mut baselines_lock = sentinel.baselines.write().await;
    for (entity_id, sessions) in grouped {
        let session_count = sessions.len() as u32;

        let mut intent_distribution: HashMap<String, u32> = HashMap::new();
        let mut known_peers = HashSet::new();
        let mut total_trust: i64 = 0;
        let mut total_bytes: i64 = 0;
        let mut hours_seen = HashSet::new();

        let mut earliest = i64::MAX;
        let mut latest = i64::MIN;

        for (started_at, intent, trust_score, dest_id, bytes_tx, bytes_rx) in &sessions {
            *intent_distribution.entry(intent.clone()).or_insert(0) += 1;
            known_peers.insert(dest_id.clone());
            total_trust += *trust_score;
            total_bytes += *bytes_tx + *bytes_rx;

            if *started_at < earliest { earliest = *started_at; }
            if *started_at > latest { latest = *started_at; }

            // Track active hours
            let hour = (started_at % 86400) / 3600;
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
        if hours_span < 0.1 { hours_span = 0.1; }
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

    state.hub.log("AI", "Sentinel: behavioral baselines updated");
}
