// AITP Client Agent — session.rs
// Active session table tracking all live SessionPermits.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::handshake::{SessionPermit, Verdict};

const SESSION_TTL_SECS: u64 = 3600; // 1 hour default

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub permit: Arc<SessionPermit>,
    pub dest_entity_id: String,
}

#[derive(Clone, Default)]
pub struct SessionTable {
    inner: Arc<RwLock<HashMap<String, SessionInfo>>>,
}

#[allow(dead_code)]
impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a session permit.
    pub fn insert(&self, session_id: String, permit: SessionPermit, dest: String) {
        let mut guard = self.inner.write().expect("session table lock poisoned");
        guard.insert(
            session_id,
            SessionInfo {
                permit: Arc::new(permit),
                dest_entity_id: dest,
            },
        );
    }

    /// Look up a session by its ID.
    pub fn get(&self, session_id: &str) -> Option<Arc<SessionPermit>> {
        let guard = self.inner.read().expect("session table lock poisoned");
        guard.get(session_id).map(|s| Arc::clone(&s.permit))
    }

    /// Remove a session (on revoke or expiry).
    pub fn remove(&self, session_id: &str) {
        let mut guard = self.inner.write().expect("session table lock poisoned");
        guard.remove(session_id);
    }

    /// Purge sessions older than TTL.
    pub fn purge_expired(&self) {
        let ttl = Duration::from_secs(SESSION_TTL_SECS);
        let mut guard = self.inner.write().expect("session table lock poisoned");
        guard.retain(|_, info| info.permit.established_at.elapsed() < ttl);
    }

    /// Return count of active sessions.
    pub fn active_count(&self) -> usize {
        self.inner
            .read()
            .expect("session table lock poisoned")
            .len()
    }

    /// Return list of all active sessions for status display.
    pub fn snapshot(&self) -> Vec<SessionSnapshot> {
        let guard = self.inner.read().expect("session table lock poisoned");
        guard
            .iter()
            .map(|(id, info)| SessionSnapshot {
                session_id: id.clone(),
                dest: info.dest_entity_id.clone(),
                verdict: info.permit.verdict.clone(),
                trust_score: info.permit.trust_score,
                age_secs: info.permit.age_secs(),
                intent: info.permit.intent.to_string(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub dest: String,
    pub verdict: Verdict,
    pub trust_score: u8,
    pub age_secs: u64,
    pub intent: String,
}
