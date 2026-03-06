use crate::db::models::WsEvent;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct WsHub {
    pub tx: broadcast::Sender<String>,
}

impl WsHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(2048);
        WsHub { tx }
    }

    pub fn broadcast(&self, event: WsEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self.tx.send(json);
        }
    }

    pub fn log(&self, level: &str, message: &str) {
        self.broadcast(WsEvent::Log {
            level: level.to_string(),
            message: message.to_string(),
            ts: chrono::Utc::now().format("%H:%M:%S%.3f").to_string(),
        });
    }

    #[allow(dead_code)]
    pub fn alert(&self, alert_type: &str, severity: &str, source_ip: &str, description: &str) {
        self.broadcast(WsEvent::Alert {
            alert_type: alert_type.to_string(),
            severity: severity.to_string(),
            source_ip: source_ip.to_string(),
            description: description.to_string(),
            ts: chrono::Utc::now().format("%H:%M:%S%.3f").to_string(),
        });
    }
}

pub mod handler;
pub use handler::ws_handler;
