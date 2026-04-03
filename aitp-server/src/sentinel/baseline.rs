use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use tokio::sync::Mutex;

use super::{Anomaly, SecurityIncident, SentinelEvent};
use crate::db::{self, DbPool};

/// Behavioral baseline for an entity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityBaseline {
    pub entity_id: String,
    pub avg_sessions_per_hour: f64,
    pub intent_distribution: HashMap<String, f64>,
    pub avg_trust_score: f64,
    pub known_peers: Vec<String>,
    pub avg_payload_bytes: f64,
    pub normal_hours: Vec<u8>,
    pub learning_complete: bool,
    pub sample_count: usize,
    pub last_updated: i64,
}

impl EntityBaseline {
    pub fn new(entity_id: &str) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            avg_sessions_per_hour: 0.0,
            intent_distribution: HashMap::new(),
            avg_trust_score: 128.0,
            known_peers: Vec::new(),
            avg_payload_bytes: 0.0,
            normal_hours: Vec::new(),
            learning_complete: false,
            sample_count: 0,
            last_updated: chrono::Utc::now().timestamp(),
        }
    }
}

/// In-memory Sentinel state — lives in AppState.sentinel
pub struct SentinelState {
    /// Behavioral baselines — loaded from DB at startup, updated in memory,
    /// flushed to DB every 60s
    /// Key: (org_id, entity_id)
    pub baselines: DashMap<(String, String), EntityBaseline>,

    /// Which baselines have unsaved changes (need DB flush)
    pub dirty_baselines: DashMap<(String, String), bool>,

    /// Recent denial timestamps per entity — for DeniedSession spike detection
    /// Key: (org_id, entity_id), Value: ring buffer of denial timestamps
    pub recent_denials: DashMap<(String, String), VecDeque<i64>>,

    /// Anomaly ring buffer — legacy support for global anomaly list
    pub anomalies: Mutex<VecDeque<Anomaly>>,

    /// Security incidents — legacy support
    pub incidents: Mutex<Vec<SecurityIncident>>,

    /// For legacy scan support — map entities to last activity instant
    pub dirty_entities: DashMap<(String, String), std::time::Instant>,
}

impl Default for SentinelState {
    fn default() -> Self {
        Self::new()
    }
}

impl SentinelState {
    pub fn new() -> Self {
        Self {
            baselines: DashMap::new(),
            dirty_baselines: DashMap::new(),
            recent_denials: DashMap::new(),
            anomalies: Mutex::new(VecDeque::with_capacity(1000)),
            incidents: Mutex::new(Vec::new()),
            dirty_entities: DashMap::new(),
        }
    }

    /// Get baseline for an entity. Returns None if not yet established.
    pub async fn get_baseline(&self, org_id: &str, entity_id: &str) -> Option<EntityBaseline> {
        self.baselines.get(&(org_id.to_string(), entity_id.to_string())).map(|b| b.clone())
    }

    /// Get or create a baseline (mutable ref for updating)
    pub async fn get_or_create_baseline(
        &self,
        org_id: &str,
        entity_id: &str,
    ) -> dashmap::mapref::one::RefMut<'_, (String, String), EntityBaseline> {
        self.baselines
            .entry((org_id.to_string(), entity_id.to_string()))
            .or_insert_with(|| EntityBaseline::new(entity_id))
    }

    pub async fn mark_baseline_dirty(&self, org_id: &str, entity_id: &str) {
        self.dirty_baselines.insert((org_id.to_string(), entity_id.to_string()), true);
    }

    pub fn mark_dirty(&self, org_id: &str, entity_id: &str) {
        self.dirty_entities
            .insert((org_id.to_string(), entity_id.to_string()), std::time::Instant::now());
    }

    pub async fn take_dirty_baselines(&self) -> Vec<(String, String)> {
        let dirty: Vec<(String, String)> = self
            .dirty_baselines
            .iter()
            .map(|r| r.key().clone())
            .collect();
        self.dirty_baselines.clear();
        dirty
    }

    /// Update the entity's baseline after a session (lightweight touch)
    pub async fn touch_baseline(&self, org_id: &str, entity_id: &str, event: &SentinelEvent) {
        let _entry = self
            .baselines
            .entry((org_id.to_string(), entity_id.to_string()))
            .or_insert_with(|| EntityBaseline::new(entity_id));

        // Track denial for spike detection
        if event.verdict == "Deny" {
            let mut denials = self
                .recent_denials
                .entry((org_id.to_string(), entity_id.to_string()))
                .or_default();
            denials.push_back(event.occurred_at);
            // Keep only last 60 seconds
            let cutoff = event.occurred_at - 60;
            while denials.front().map(|&t| t < cutoff).unwrap_or(false) {
                denials.pop_front();
            }
        }
    }

    /// Count recent denials in the last `window_secs` for spike detection
    pub fn count_recent_denials(&self, org_id: &str, entity_id: &str, window_secs: i64) -> u32 {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - window_secs;

        self.recent_denials
            .get(&(org_id.to_string(), entity_id.to_string()))
            .map(|denials| denials.iter().filter(|&&t| t >= cutoff).count() as u32)
            .unwrap_or(0)
    }

    /// Load all baselines from DB at startup
    pub async fn load_from_db(&self, db: &DbPool, org_id: &str) -> anyhow::Result<()> {
        let baselines = db::get_all_baselines(db, org_id).await?;
        for baseline in baselines {
            self.baselines.insert((org_id.to_string(), baseline.entity_id.clone()), baseline);
        }
        tracing::info!(
            "Loaded {} entity baselines into Sentinel cache",
            self.baselines.len()
        );
        Ok(())
    }
}
