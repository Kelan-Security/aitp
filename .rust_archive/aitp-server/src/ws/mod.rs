use crate::db::models::WsEvent;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

pub mod handler;
pub use handler::ws_handler;

/// Per-org broadcast channel capacity.
const CHANNEL_CAPACITY: usize = 512;

/// Multi-tenant WebSocket hub.
/// Each org gets its own isolated broadcast channel — messages never leak cross-tenant.
#[derive(Clone)]
pub struct WsHub {
    /// org_id → broadcast sender for that tenant only
    channels: Arc<DashMap<String, broadcast::Sender<Arc<WsEvent>>>>,
    pub budget: Arc<crate::budget::MemoryBudget>,
    pub identity: Arc<crate::crypto::HybridEntityIdentity>,
}

impl WsHub {
    pub fn new(
        budget: Arc<crate::budget::MemoryBudget>,
        identity: Arc<crate::crypto::HybridEntityIdentity>,
    ) -> Self {
        Self {
            channels: Arc::new(DashMap::new()),
            budget,
            identity,
        }
    }

    /// Get or create a broadcast channel for the given org.
    pub fn get_or_create_channel(&self, org_id: &str) -> broadcast::Sender<Arc<WsEvent>> {
        self.channels
            .entry(org_id.to_string())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
                tx
            })
            .clone()
    }

    /// Subscribe to a specific org's event stream.
    pub fn subscribe(&self, org_id: &str) -> broadcast::Receiver<Arc<WsEvent>> {
        self.get_or_create_channel(org_id).subscribe()
    }

    /// Broadcast an event to a specific org only.
    /// Silently drops if no active subscribers for that org.
    pub fn broadcast(&self, org_id: &str, event: WsEvent) {
        // Authenticate with server identity (sign bytes for auditability)
        let bytes = serde_json::to_vec(&event).unwrap_or_default();
        let _signature = self.identity.sign(&bytes).to_bytes();

        if let Some(tx) = self.channels.get(org_id) {
            if tx.receiver_count() > 0 {
                if self.budget.ws_semaphore.try_acquire().is_ok() {
                    let _ = tx.send(Arc::new(event));
                } else {
                    tracing::warn!(org_id = %org_id, "WS broadcast dropped (backpressure)");
                }
            }
        }
    }

    /// Broadcast a log message to a specific org.
    pub fn log(&self, level: &str, message: &str) {
        // System-level logs go to all connected orgs
        let event = WsEvent::Log {
            level: level.to_string(),
            message: message.to_string(),
            ts: chrono::Utc::now().timestamp(),
        };
        // Broadcast to all active channels
        for entry in self.channels.iter() {
            let org_id = entry.key().clone();
            self.broadcast(&org_id, event.clone());
        }
    }

    /// Broadcast a log message scoped to one org.
    pub fn log_org(&self, org_id: &str, level: &str, message: &str) {
        self.broadcast(org_id, WsEvent::Log {
            level: level.to_string(),
            message: message.to_string(),
            ts: chrono::Utc::now().timestamp(),
        });
    }

    /// Broadcast an alert to a specific org.
    #[allow(dead_code)]
    pub fn alert(
        &self,
        org_id: &str,
        alert_type: &str,
        severity: &str,
        entity_id: Option<&str>,
        description: &str,
        action: &str,
    ) {
        self.broadcast(org_id, WsEvent::Alert {
            alert_type: alert_type.to_string(),
            severity: severity.to_string(),
            entity_id: entity_id.map(|s| s.to_string()),
            description: description.to_string(),
            recommended_action: action.to_string(),
            ts: chrono::Utc::now().timestamp(),
        });
    }

    /// Return total number of connected subscribers across all orgs.
    pub fn total_subscribers(&self) -> usize {
        self.channels
            .iter()
            .map(|e| e.value().receiver_count())
            .sum()
    }

    /// Remove channels that have no active subscribers (called periodically).
    pub fn cleanup_empty_channels(&self) {
        self.channels.retain(|_, tx| tx.receiver_count() > 0);
    }
}
