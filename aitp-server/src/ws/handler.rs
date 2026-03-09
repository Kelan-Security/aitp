use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    auth::{validate_token, AitpClaims},
    db::models::WsEvent,
    state::AppState,
};

/// WebSocket upgrade handler — GET /ws?token=<JWT>
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let token = match params.get("token") {
        Some(t) => t.clone(),
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    // Validate the real JWT — NO bypasses
    let claims = match validate_token(&state.config.token_config, &token) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("WebSocket auth failed: {}", e);
            return (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e)).into_response();
        }
    };

    ws.on_upgrade(move |sock| handle_socket(sock, state, claims))
}

async fn handle_socket(mut sock: WebSocket, state: Arc<AppState>, claims: AitpClaims) {
    let org_id = claims.org_id;

    // Look up org for welcome message
    let org_name = state
        .db
        .get_org_by_id(&org_id)
        .await
        .map(|o| o.name)
        .unwrap_or_else(|_| "Unknown".to_string());

    // Send welcome event
    if let Ok(json) = serde_json::to_string(&WsEvent::Connected {
        org_id: org_id.clone(),
        org_name,
    }) {
        let _ = sock.send(Message::Text(json)).await;
    }

    // Replay last 20 audit entries as log messages
    if let Ok(entries) = state.db.get_recent_audit(&org_id, 20).await {
        for e in entries.into_iter().rev() {
            let ws_event = WsEvent::Log {
                level: e.severity,
                message: e.description,
                ts: e.created_at,
            };
            if let Ok(json) = serde_json::to_string(&ws_event) {
                let _ = sock.send(Message::Text(json)).await;
            }
        }
    }

    // Subscribe to broadcast channel
    let mut rx = state.hub.tx.subscribe();

    loop {
        tokio::select! {
            // Forward broadcast events to this client
            result = rx.recv() => {
                match result {
                    Ok(json) => {
                        if sock.send(Message::Text(json)).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket client lagged by {} messages", n);
                    }
                    Err(_) => break,
                }
            }
            // Handle messages from client
            msg = sock.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_client_cmd(&text, &org_id, &state).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {} // Ignore binary/ping/pong
                }
            }
        }
    }
}

/// Handle commands sent from the dashboard client.
async fn handle_client_cmd(text: &str, org_id: &str, state: &Arc<AppState>) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        match v["cmd"].as_str() {
            Some("revoke") => {
                if let Some(sid) = v["session_id"].as_str() {
                    state.hub.log(
                        "WARN",
                        &format!("Session {} revoked via dashboard by org {}", sid, org_id),
                    );
                    let _ = state.db.revoke_session(sid).await;
                }
            }
            Some("ping") => {} // Keepalive
            _ => {}
        }
    }
}
