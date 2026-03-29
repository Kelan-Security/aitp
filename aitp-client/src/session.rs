// Kelan Security Client Agent — session.rs
// Active session table tracking all live SessionPermits.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::handshake::SessionPermit;

#[derive(Clone)]
pub struct SessionTable {
    inner: Arc<RwLock<HashMap<u64, SessionPermit>>>,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert or replace a session permit.
    pub async fn insert(&self, session_id: u64, permit: SessionPermit) {
        self.inner.write().await.insert(session_id, permit);
    }

    /// Look up a session by its ID.
    #[allow(dead_code)]
    pub async fn get(&self, session_id: u64) -> Option<SessionPermit> {
        self.inner.read().await.get(&session_id).cloned()
    }

    /// Remove a session (on revoke or expiry).
    pub async fn remove(&self, session_id: u64) {
        self.inner.write().await.remove(&session_id);
    }

    /// Revoke ALL active sessions (quarantine).
    pub async fn revoke_all(&self) {
        self.inner.write().await.clear();
    }

    /// Purge sessions older than their expiry.
    pub async fn purge_expired(&self) {
        let now = std::time::Instant::now();
        self.inner
            .write()
            .await
            .retain(|_, permit| permit.expires_at > now);
    }

    /// Return count of active sessions.
    pub async fn active_count(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Snapshot for status display.
    pub async fn snapshot(&self) -> Vec<SessionSnapshot> {
        let guard = self.inner.read().await;
        guard
            .iter()
            .map(|(id, permit)| SessionSnapshot {
                session_id: format!("{:016x}", id),
                trust_score: permit.trust_score,
                verdict: permit.verdict.to_string(),
                intent: permit.intent.to_string(),
                age_secs: permit
                    .expires_at
                    .checked_duration_since(std::time::Instant::now())
                    .map(|d| 3600u64.saturating_sub(d.as_secs()))
                    .unwrap_or(3600),
            })
            .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub trust_score: u8,
    pub verdict: String,
    pub intent: String,
    pub age_secs: u64,
}
