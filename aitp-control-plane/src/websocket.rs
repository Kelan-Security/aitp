use aitp_core::events::{AitpEvent, AitpEventKind};
use serde_json::json;
use socketioxide::{
    extract::{Data, SocketRef},
    SocketIo,
};
use tracing::info;

/// Initialize Socket.IO handlers and start the event bridge.
pub fn init_socket_handlers(io: SocketIo) {
    io.ns("/", on_connect);
}

/// Handler for new WebSocket connections.
fn on_connect(socket: SocketRef) {
    info!("Dashboard connected: {}", socket.id);

    socket.on(
        "auth",
        |socket: SocketRef, Data(data): Data<serde_json::Value>| {
            info!("Authentication attempt from {}: {:?}", socket.id, data);
            // Simple mock auth for prototype
            socket
                .emit("auth_success", json!({ "status": "authorized" }))
                .ok();
        },
    );
}

/// Bridges internal AITP events to connected WebSocket clients.
pub async fn bridge_events(io: SocketIo, mut rx: tokio::sync::broadcast::Receiver<AitpEvent>) {
    info!("AITP WebSocket Event Bridge started");

    while let Ok(event) = rx.recv().await {
        let event_name = match &event.kind {
            AitpEventKind::SessionInitiated { .. } => "session.established",
            AitpEventKind::SessionRevoked { .. } => "session.revoked",
            AitpEventKind::PacketDropped { .. } => "attack.detected",
            _ => "metrics.update",
        };

        // Transform internal event for frontend consumption
        let payload = match &event.kind {
            AitpEventKind::SessionInitiated {
                session_id,
                source,
                dest,
                intent,
            } => {
                json!({
                    "id": format!("{:#018x}", session_id),
                    "source": hex::encode(source),
                    "destination": hex::encode(dest),
                    "intent": format!("{:04x}", intent),
                    "trust_score": 255, // Initial
                    "status": "ESTABLISHED"
                })
            }
            AitpEventKind::PacketDropped { reason, .. } => {
                json!({
                    "type": "PACKET_DROPPED",
                    "detail": reason.to_string(),
                    "src": "EXTERNAL"
                })
            }
            _ => json!(event.kind),
        };

        let _ = io.emit(event_name, payload);
    }
}
