use std::sync::Arc;
use tokio::time::Instant;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::sentinel::{SentinelEvent, SentinelState};
use crate::ws::WsHub;
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc, broadcast};

use crate::budget::MemoryBudget;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentVerdictSync {
    pub entity_id: String,
    pub session_id: String,
    pub verdict: String,   // ALLOW, DENY, MONITOR
    pub confidence: f32,
    pub timestamp: i64,
    pub action: String,    // PERMIT, REVOKE
}

/// Shared application state, wrapped in Arc for concurrent access.
pub struct AppState {
    pub db: DbPool,
    pub hub: WsHub,
    pub config: AppConfig,
    pub start_time: Instant,
    pub sentinel: Arc<SentinelState>,
    pub sentinel_tx: mpsc::Sender<SentinelEvent>,
    pub trust_engine: crate::trust::HybridTrustEngine,
    pub memory_budget: Arc<MemoryBudget>,
    pub enforcer: Arc<crate::enforcement::BpfEnforcer>,
    pub server_identity: Arc<crate::crypto::HybridEntityIdentity>,
    pub ollama_client: Arc<crate::ai::OllamaClient>,
    pub sessions: tokio::sync::RwLock<crate::protocol::session::SessionManager>,
    pub handshakes: tokio::sync::RwLock<crate::protocol::handshake::HandshakeManager>,
    pub verdict_tx: broadcast::Sender<AgentVerdictSync>,
    pub simulation_active: std::sync::atomic::AtomicBool,
}

impl AppState {
    /// Publish a session event to the Sentinel.
    /// Never blocks. If channel is full, event is silently dropped
    /// (the 60s background scan catches anything missed).
    pub fn send_sentinel_event(&self, event: SentinelEvent) {
        if let Err(e) = self.sentinel_tx.try_send(event) {
            tracing::trace!("Sentinel channel full, event dropped: {}", e);
        }
    }
}
