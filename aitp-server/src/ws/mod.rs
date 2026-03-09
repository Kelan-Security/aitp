use crate::db::models::WsEvent;
use tokio::sync::broadcast;

pub mod handler;
pub use handler::ws_handler;

/// WebSocket hub — broadcasts events to all connected dashboard clients.
#[derive(Clone)]
pub struct WsHub {
    pub tx: broadcast::Sender<String>,
}

impl WsHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        WsHub { tx }
    }

    /// Broadcast a WsEvent to all connected clients.
    pub fn broadcast(&self, event: WsEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self.tx.send(json);
        }
    }

    /// Helper: broadcast a log message.
    pub fn log(&self, level: &str, message: &str) {
        self.broadcast(WsEvent::Log {
            level: level.to_string(),
            message: message.to_string(),
            ts: chrono::Utc::now().timestamp(),
        });
    }

    /// Helper: broadcast an alert.
    #[allow(dead_code)]
    pub fn alert(
        &self,
        alert_type: &str,
        severity: &str,
        entity_id: Option<&str>,
        description: &str,
        action: &str,
    ) {
        self.broadcast(WsEvent::Alert {
            alert_type: alert_type.to_string(),
            severity: severity.to_string(),
            entity_id: entity_id.map(|s| s.to_string()),
            description: description.to_string(),
            recommended_action: action.to_string(),
            ts: chrono::Utc::now().timestamp(),
        });
    }
}
