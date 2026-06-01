use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
};
// (No unused imports)
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
    let org_id = claims.org_id.clone();

    // Look up org for welcome message
    let org_name = state
        .db
        .get_org_by_id(&org_id)
        .await
        .map(|o| o.name)
        .unwrap_or_else(|_| "Unknown".to_string());

    // Send welcome event scoped to this org
    if let Ok(json) = serde_json::to_string(&WsEvent::Connected {
        org_id: org_id.clone(),
        org_name,
    }) {
        let _ = sock.send(Message::Text(json)).await;
    }

    // Replay last 20 audit entries as log messages for this org only
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

    // FIX 5: Subscribe to THIS org's isolated channel only
    let mut rx = state.hub.subscribe(&org_id);

    loop {
        tokio::select! {
            // Forward org-scoped broadcast events to this client
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        let json_str = match serde_json::to_string(&*event) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!("Failed to serialize WsEvent: {}", e);
                                continue;
                            }
                        };
                        if sock.send(Message::Text(json_str)).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(org_id = %org_id, "WS client lagged {} messages", n);
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

    tracing::info!(org_id = %org_id, "WebSocket client disconnected");
}

/// Handle commands sent from the dashboard client.
async fn handle_client_cmd(text: &str, org_id: &str, state: &Arc<AppState>) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        match v["cmd"].as_str() {
            Some("revoke") => {
                if let Some(sid) = v["session_id"].as_str() {
                    state.hub.log_org(
                        org_id,
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
