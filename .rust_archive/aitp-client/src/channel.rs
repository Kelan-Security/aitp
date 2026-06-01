// Kelan Security Client Agent — channel.rs
// Persistent WebSocket to Intelligence Core for receiving commands.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;

use crate::config::AgentConfig;
use crate::interceptor::proxy::QUARANTINE_FLAG;
use crate::session::SessionTable;

pub struct IcChannel {
    config: Arc<AgentConfig>,
    sessions: SessionTable,
}

impl IcChannel {
    pub fn new(config: Arc<AgentConfig>, sessions: SessionTable) -> Self {
        Self { config, sessions }
    }

    pub async fn run(&self) {
        loop {
            let token = match &self.config.agent.api_token {
                Some(t) => t.clone(),
                None => {
                    tracing::warn!("No API token — channel disabled. Run: kelan-agent enroll");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            };

            let ws_url = self.config.ws_url(&token);
            tracing::info!("Connecting command channel: {}", ws_url);

            match tokio_tungstenite::connect_async(&ws_url).await {
                Ok((ws, _)) => {
                    tracing::info!("Command channel connected to Intelligence Core");
                    self.handle_messages(ws).await;
                    tracing::warn!("Command channel disconnected — reconnecting in 5s");
                }
                Err(e) => {
                    tracing::warn!("Command channel connection failed: {} — retry in 10s", e);
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn handle_messages(
        &self,
        ws: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) {
        let (_, mut read) = ws.split();

        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Ok(cmd) = serde_json::from_str::<IcCommand>(&text) {
                        self.handle_command(cmd).await;
                    }
                }
                Ok(Message::Close(_)) => break,
                Err(e) => {
                    tracing::warn!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    }

    async fn handle_command(&self, cmd: IcCommand) {
        match cmd {
            IcCommand::Quarantine { reason } => {
                tracing::warn!("QUARANTINE received: {}", reason);
                self.sessions.revoke_all().await;
                QUARANTINE_FLAG.store(true, Ordering::SeqCst);
                tracing::warn!("Agent quarantined — all sessions revoked, new connections blocked");
            }
            IcCommand::Release { reason } => {
                tracing::info!("RELEASE received: {}", reason);
                QUARANTINE_FLAG.store(false, Ordering::SeqCst);
                tracing::info!("Agent released from quarantine");
            }
            IcCommand::RevokeSession { session_id } => {
                self.sessions.remove(session_id).await;
                tracing::info!(session_id, "Session revoked by IC");
            }
            IcCommand::Ping => {}
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IcCommand {
    Quarantine {
        reason: String,
    },
    Release {
        reason: String,
    },
    #[serde(rename = "revoke_session")]
    RevokeSession {
        session_id: u64,
    },
    Ping,
}
