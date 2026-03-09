// AITP Client Agent — ipc.rs
// Unix socket IPC server for `aitp-client status` queries.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::session::SessionTable;

pub const IPC_SOCKET_PATH: &str = "/tmp/aitp-client.sock";

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub entity_id: String,
    pub public_key: String,
    pub server_connected: bool,
    pub server_address: String,
    pub active_sessions: usize,
    pub uptime_secs: u64,
    pub interception_mode: String,
    pub sessions: Vec<SessionEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionEntry {
    pub session_id: String,
    pub dest: String,
    pub verdict: String,
    pub trust_score: u8,
    pub age_secs: u64,
    pub intent: String,
}

/// Query the running daemon for its status via IPC.
pub async fn query_status() -> Result<StatusResponse> {
    let path = PathBuf::from(IPC_SOCKET_PATH);
    if !path.exists() {
        anyhow::bail!("AITP daemon is not running (socket not found: {})", IPC_SOCKET_PATH);
    }
    let mut stream = UnixStream::connect(&path).await?;
    stream.write_all(b"STATUS\n").await?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf).await?;
    let status: StatusResponse = serde_json::from_str(&buf)?;
    Ok(status)
}

/// Start the IPC server in the background and handle `STATUS` queries.
pub async fn start_ipc_server(
    daemon_state: std::sync::Arc<DaemonState>,
) -> Result<()> {
    let path = PathBuf::from(IPC_SOCKET_PATH);
    // Remove stale socket file
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    tracing::info!("IPC server listening on {}", IPC_SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = std::sync::Arc::clone(&daemon_state);
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc_connection(stream, state).await {
                        tracing::warn!("IPC error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("IPC accept error: {}", e);
            }
        }
    }
}

async fn handle_ipc_connection(
    mut stream: UnixStream,
    state: std::sync::Arc<DaemonState>,
) -> Result<()> {
    let mut cmd = String::new();
    stream.read_to_string(&mut cmd).await?;
    let cmd = cmd.trim();

    match cmd {
        "STATUS" => {
            let sessions: Vec<SessionEntry> = state
                .sessions
                .snapshot()
                .into_iter()
                .map(|s| SessionEntry {
                    session_id: s.session_id[..s.session_id.len().min(16)].to_string() + "...",
                    dest: s.dest[..s.dest.len().min(16)].to_string() + "...",
                    verdict: format!("{:?}", s.verdict),
                    trust_score: s.trust_score,
                    age_secs: s.age_secs,
                    intent: s.intent,
                })
                .collect();

            let response = StatusResponse {
                entity_id: state.entity_id_short.clone(),
                public_key: state.public_key_hex.clone(),
                server_connected: *state.connected.lock().await,
                server_address: state.server_address.clone(),
                active_sessions: state.sessions.active_count(),
                uptime_secs: state.started_at.elapsed().as_secs(),
                interception_mode: state.interception_mode.clone(),
                sessions,
            };

            let json = serde_json::to_string(&response)?;
            stream.write_all(json.as_bytes()).await?;
        }
        _ => {
            stream.write_all(b"\"ERROR: unknown command\"").await?;
        }
    }

    Ok(())
}

/// Shared state accessible from the IPC server.
pub struct DaemonState {
    pub entity_id_short: String,
    pub public_key_hex: String,
    pub connected: tokio::sync::Mutex<bool>,
    pub server_address: String,
    pub sessions: SessionTable,
    pub started_at: std::time::Instant,
    pub interception_mode: String,
}
