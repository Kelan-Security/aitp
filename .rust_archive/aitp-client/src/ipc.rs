// Kelan Security Client Agent — ipc.rs
// Unix socket for `kelan-agent status` queries.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use crate::config::AgentConfig;
use crate::identity::EntityIdentity;
use crate::session::SessionTable;

pub const IPC_SOCKET_PATH: &str = "/tmp/kelan-agent.sock";

/// Start the IPC server that responds to status queries.
pub async fn start_ipc_server(
    sessions: SessionTable,
    config: Arc<AgentConfig>,
    identity: Arc<EntityIdentity>,
) -> anyhow::Result<()> {
    // Remove stale socket
    let _ = std::fs::remove_file(IPC_SOCKET_PATH);

    let listener = UnixListener::bind(IPC_SOCKET_PATH)?;
    tracing::debug!("IPC server listening on {}", IPC_SOCKET_PATH);

    loop {
        let (mut stream, _) = listener.accept().await?;
        let sessions = sessions.clone();
        let config = Arc::clone(&config);
        let identity = Arc::clone(&identity);

        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let cmd = String::from_utf8_lossy(&buf[..n]);

            if cmd.trim() == "status" {
                let status = AgentStatus {
                    running: true,
                    entity_id: identity.short_id(),
                    ic_connected: config.agent.api_token.is_some(),
                    active_sessions: sessions.active_count().await,
                    blocked_today: 0, // TODO: track from metrics
                    mode: config.interception.mode.to_string(),
                    proxy_port: config.interception.proxy_port,
                    sessions: sessions.snapshot().await,
                };

                let json = serde_json::to_string(&status).unwrap_or_default();
                let _ = stream.write_all(json.as_bytes()).await;
            }
        });
    }
}

/// Query the IPC socket for agent status.
pub async fn query_status() -> anyhow::Result<AgentStatus> {
    let mut stream = tokio::net::UnixStream::connect(IPC_SOCKET_PATH)
        .await
        .map_err(|_| anyhow::anyhow!("Cannot connect to agent — is it running?"))?;

    stream.write_all(b"status").await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    let status: AgentStatus = serde_json::from_slice(&buf)?;
    Ok(status)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AgentStatus {
    pub running: bool,
    pub entity_id: String,
    pub ic_connected: bool,
    pub active_sessions: usize,
    pub blocked_today: u64,
    pub mode: String,
    pub proxy_port: u16,
    pub sessions: Vec<crate::session::SessionSnapshot>,
}
