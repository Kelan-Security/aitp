use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::IntentCode;

// ────────────────────────── Session Permit ──────────────────────────

/// A permit represents an allowed active session in the enforcement layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPermit {
    pub session_id: String,
    pub source_entity_id: String,
    pub dest_entity_id: String,
    pub intent: IntentCode,
    pub trust_score: u8,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
}

// ────────────────────────── Active Session ──────────────────────────

/// Runtime representation of an active session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub id: String,
    pub source_entity_id: String,
    pub dest_entity_id: String,
    pub intent: IntentCode,
    pub trust_score: u8,
    pub verdict: String,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub started_at: i64,
    pub last_activity: i64,
    pub anomaly_flags: Vec<String>,
    #[serde(skip)]
    pub session_key: Option<[u8; 32]>,
}

/// Manages active sessions in memory.
pub struct SessionManager {
    sessions: HashMap<String, ActiveSession>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Register a new active session.
    pub fn create(&mut self, session: ActiveSession) {
        self.sessions.insert(session.id.clone(), session);
    }

    /// Get a session by ID.
    pub fn get(&self, session_id: &str) -> Option<&ActiveSession> {
        self.sessions.get(session_id)
    }

    /// Update bytes transferred for a session.
    pub fn update_bytes(&mut self, session_id: &str, tx: u64, rx: u64) {
        if let Some(s) = self.sessions.get_mut(session_id) {
            s.bytes_tx += tx;
            s.bytes_rx += rx;
            s.last_activity = chrono::Utc::now().timestamp();
        }
    }

    /// Add an anomaly flag to a session.
    pub fn add_anomaly_flag(&mut self, session_id: &str, flag: String) {
        if let Some(s) = self.sessions.get_mut(session_id) {
            if !s.anomaly_flags.contains(&flag) {
                s.anomaly_flags.push(flag);
            }
        }
    }

    /// Remove and return a session (close/revoke).
    pub fn remove(&mut self, session_id: &str) -> Option<ActiveSession> {
        self.sessions.remove(session_id)
    }

    /// Get all sessions for an entity.
    pub fn sessions_for_entity(&self, entity_id: &str) -> Vec<&ActiveSession> {
        self.sessions
            .values()
            .filter(|s| s.source_entity_id == entity_id || s.dest_entity_id == entity_id)
            .collect()
    }

    /// Revoke all sessions for an entity. Returns number of sessions killed.
    pub fn revoke_all_for_entity(&mut self, entity_id: &str) -> Vec<ActiveSession> {
        let ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.source_entity_id == entity_id || s.dest_entity_id == entity_id)
            .map(|(id, _)| id.clone())
            .collect();

        ids.into_iter()
            .filter_map(|id| self.sessions.remove(&id))
            .collect()
    }

    /// Number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Expire sessions inactive for longer than `timeout_secs`.
    pub fn expire_inactive(&mut self, timeout_secs: i64) -> Vec<ActiveSession> {
        let now = chrono::Utc::now().timestamp();
        let expired_ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| now - s.last_activity > timeout_secs)
            .map(|(id, _)| id.clone())
            .collect();

        expired_ids
            .into_iter()
            .filter_map(|id| self.sessions.remove(&id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(id: &str) -> ActiveSession {
        ActiveSession {
            id: id.to_string(),
            source_entity_id: "entity_a".to_string(),
            dest_entity_id: "entity_b".to_string(),
            intent: IntentCode::ModelInference,
            trust_score: 200,
            verdict: "Allow".to_string(),
            bytes_tx: 0,
            bytes_rx: 0,
            started_at: chrono::Utc::now().timestamp(),
            last_activity: chrono::Utc::now().timestamp(),
            anomaly_flags: vec![],
            session_key: None,
        }
    }

    #[test]
    fn test_session_lifecycle() {
        let mut mgr = SessionManager::new();
        mgr.create(make_session("s1"));
        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.get("s1").is_some());

        mgr.update_bytes("s1", 1024, 512);
        let s = mgr.get("s1").unwrap();
        assert_eq!(s.bytes_tx, 1024);
        assert_eq!(s.bytes_rx, 512);

        let removed = mgr.remove("s1");
        assert!(removed.is_some());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_session_anomaly_flags() {
        let mut mgr = SessionManager::new();
        mgr.create(make_session("s2"));
        mgr.add_anomaly_flag("s2", "TrustScoreDrop".to_string());
        mgr.add_anomaly_flag("s2", "TrustScoreDrop".to_string()); // dupe
        let s = mgr.get("s2").unwrap();
        assert_eq!(s.anomaly_flags.len(), 1);
    }

    #[test]
    fn test_revoke_all_for_entity() {
        let mut mgr = SessionManager::new();
        mgr.create(make_session("s3"));
        mgr.create(ActiveSession {
            id: "s4".to_string(),
            source_entity_id: "entity_a".to_string(),
            dest_entity_id: "entity_c".to_string(),
            intent: IntentCode::DataSync,
            trust_score: 150,
            verdict: "Allow".to_string(),
            bytes_tx: 0,
            bytes_rx: 0,
            started_at: chrono::Utc::now().timestamp(),
            last_activity: chrono::Utc::now().timestamp(),
            anomaly_flags: vec![],
            session_key: Some([0u8; 32]),
        });
        mgr.create(ActiveSession {
            id: "s5".to_string(),
            source_entity_id: "entity_x".to_string(),
            dest_entity_id: "entity_y".to_string(),
            intent: IntentCode::Heartbeat,
            trust_score: 200,
            verdict: "Allow".to_string(),
            bytes_tx: 0,
            bytes_rx: 0,
            started_at: chrono::Utc::now().timestamp(),
            last_activity: chrono::Utc::now().timestamp(),
            anomaly_flags: vec![],
            session_key: None,
        });

        let killed = mgr.revoke_all_for_entity("entity_a");
        assert_eq!(killed.len(), 2);
        assert_eq!(mgr.active_count(), 1); // s5 remains
    }
}
