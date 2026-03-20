use std::sync::Arc;
use tokio::time::Instant;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::sentinel::{SentinelState, SentinelEvent};
use tokio::sync::mpsc;
use crate::ws::WsHub;

use crate::budget::MemoryBudget;

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
