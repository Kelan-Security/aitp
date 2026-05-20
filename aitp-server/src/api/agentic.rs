// Agentic session management — allows Kali eBPF enforcer
// to sync verdicts from macOS trust engine in real-time.

use axum::{
    extract::{State, WebSocketUpgrade, ws::{WebSocket, Message}},
    response::Response,
};
use std::sync::Arc;
use crate::state::AppState;

// WebSocket endpoint for real-time verdict sync
pub async fn ws_agentic_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(|socket| handle_agent_socket(socket, state))
}

async fn handle_agent_socket(mut socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("Kali agent connected via WebSocket");

    // Subscribe to verdict broadcast channel
    let mut rx = state.verdict_tx.subscribe();

    loop {
        tokio::select! {
            // Forward verdicts to Kali enforcer
            Ok(verdict) = rx.recv() => {
                let msg = serde_json::to_string(&verdict).unwrap();
                if socket.send(Message::Text(msg)).await.is_err() {
                    tracing::warn!("Agent disconnected");
                    break;
                }
            }
            // Receive ACKs from Kali
            Some(Ok(msg)) = socket.recv() => {
                if let Message::Text(ack) = msg {
                    tracing::debug!("Agent ACK: {}", ack);
                }
            }
            else => break,
        }
    }
}
