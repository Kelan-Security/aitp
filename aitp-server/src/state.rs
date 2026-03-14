use std::sync::Arc;
use tokio::time::Instant;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::sentinel::Sentinel;
use crate::ws::WsHub;

use crate::budget::MemoryBudget;

/// Shared application state, wrapped in Arc for concurrent access.
pub struct AppState {
    pub db: DbPool,
    pub hub: WsHub,
    pub config: AppConfig,
    pub start_time: Instant,
    pub sentinel: Arc<Sentinel>,
    pub trust_engine: crate::trust::HybridTrustEngine,
    pub memory_budget: Arc<MemoryBudget>,
}
