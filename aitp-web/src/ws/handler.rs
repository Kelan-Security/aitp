use crate::{db::models::WsEvent, state::AppState};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use std::sync::Arc;

#[derive(serde::Deserialize)]
pub struct WsParams {
    pub token: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(p): Query<WsParams>,
    State(s): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |sock| handle(sock, s, p.token))
}

async fn handle(mut sock: WebSocket, state: Arc<AppState>, token: Option<String>) {
    let org_id = match crate::auth::validate_token(token.as_deref(), &state.config.jwt_secret) {
        Some(id) => id,
        None => {
            let _ = sock
                .send(Message::Text(
                    r#"{"type":"error","message":"unauthorized"}"#.into(),
                ))
                .await;
            return;
        }
    };

    let org = match state.db.get_org_by_id(&org_id).await {
        Ok(o) => o,
        Err(_) => return,
    };

    // Send welcome
    if let Ok(j) = serde_json::to_string(&WsEvent::Connected {
        org_id: org.id.clone(),
        org_name: org.name.clone(),
    }) {
        let _ = sock.send(Message::Text(j)).await;
    }

    // Replay last 20 log lines from DB
    if let Ok(events) = state.db.get_recent_events(&org_id, 20).await {
        for e in events.into_iter().rev() {
            let ts = chrono::DateTime::from_timestamp(e.created_at, 0)
                .unwrap_or_default()
                .format("%H:%M:%S%.3f")
                .to_string();
            let ws_e = WsEvent::Log {
                level: e.severity,
                message: e.description,
                ts,
            };
            if let Ok(j) = serde_json::to_string(&ws_e) {
                let _ = sock.send(Message::Text(j)).await;
            }
        }
    }

    let mut rx = state.hub.tx.subscribe();
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(json) => {
                        if sock.send(Message::Text(json)).await.is_err() { break; }
                    }
                    Err(_) => break, // Channel lagged or closed
                }
            }
            msg = sock.recv() => {
                match msg {
                    Some(Ok(Message::Text(t))) => handle_cmd(&t, &org_id, &state).await,
                    Some(Ok(Message::Close(_))) | None => break, // Client disconnected
                    _ => {} // Ignore other messages for now
                }
            }
        }
    }
}

async fn handle_cmd(text: &str, org_id: &str, state: &Arc<AppState>) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        match v["cmd"].as_str() {
            Some("revoke") => {
                if let Some(sid) = v["session_id"].as_str() {
                    state.hub.log(
                        "WARN",
                        &format!("Session {} revoked via dashboard by org {}", sid, org_id),
                    );
                    state
                        .db
                        .close_session(sid, "dashboard_revoke", 0, 0)
                        .await
                        .ok();
                }
            }
            Some("ping") => {}
            _ => {}
        }
    }
}
