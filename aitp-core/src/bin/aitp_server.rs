/// `aitp_server` — AITP Server with live terminal dashboard.
///
/// # Usage
/// ```bash
/// aitp-server --port 9999 --dev-mode
/// aitp-server --port 9999 --gemini-key $GEMINI_API_KEY --trust-mode hybrid
/// ```
use aitp_core::events::EventBus;
use aitp_core::header::DEFAULT_UDP_PORT;
use aitp_core::server::alert_engine::AlertEngine;
use aitp_core::server::state::{ConnectedClient, LogEntry, LogLevel, ServerState};
use aitp_core::server::tui;
use aitp_core::transport::{AitpTransport, DDoSConfig, TransportConfig, TransportEvent};
use aitp_identity::identity::{AitpIdentity, Capability, EntityType};
use chrono::Utc;
use clap::Parser;
use colored::Colorize;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, IsTerminal};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// ────────────────────────── CLI ──────────────────────────

#[derive(Parser)]
#[command(
    name = "aitp-server",
    about = "AITP Server — identity-first AI transport node with live TUI dashboard",
    version = "0.2.0"
)]
struct Cli {
    /// UDP port to listen on.
    #[arg(long, default_value_t = DEFAULT_UDP_PORT, env = "AITP_PORT")]
    port: u16,

    /// Path to Ed25519 identity key file (PEM). Generated if missing.
    #[arg(long, default_value = "server.key", env = "AITP_IDENTITY")]
    identity: PathBuf,

    /// Gemini API key for AI trust evaluation.
    #[arg(long, env = "AITP_GEMINI_API_KEY")]
    gemini_key: Option<String>,

    /// Trust evaluation mode: `hybrid` (rules + AI) | `rules-only` | `ai-only`.
    #[arg(long, default_value = "rules-only", env = "AITP_TRUST_MODE")]
    trust_mode: String,

    /// Log level: error | warn | info | debug | trace.
    #[arg(long, default_value = "info", env = "AITP_LOG_LEVEL")]
    log_level: String,

    /// Development mode: verbose logging, no eBPF, relaxed trust thresholds.
    #[arg(long)]
    dev_mode: bool,

    /// Maximum concurrent sessions.
    #[arg(long, default_value_t = 10_000, env = "AITP_MAX_SESSIONS")]
    max_sessions: usize,

    /// Force JSON log output (no TUI). Auto-detected for non-TTY.
    #[arg(long)]
    json_logs: bool,
}

// ────────────────────────── Main ──────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Detect if we should use TUI or plain logs (Docker / pipe / --json-logs).
    let use_tui = !cli.json_logs && io::stdout().is_terminal();

    // Initialise identity.
    let identity = load_or_generate_identity(&cli.identity)?;
    let identity = Arc::new(identity);
    let identity_hex = hex_encode(&identity.entity_id);

    // Bind address.
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", cli.port).parse()?;

    // Transport config.
    let config = TransportConfig {
        bind_addr,
        max_sessions: cli.max_sessions,
        ddos: DDoSConfig::default(),
        ..Default::default()
    };

    // Bind transport + event channel.
    let (transport, mut event_rx) = AitpTransport::bind_with_coordinator(
        config,
        identity.clone(),
        Arc::new(aitp_ai_engine::engine::TrustEngine::with_defaults()),
    )
    .await?;

    let event_bus: EventBus = transport.event_bus().clone();

    // Shared server state.
    let state = Arc::new(ServerState::new());

    // Spawn alert engine.
    {
        let bus_rx = event_bus.subscribe();
        let engine = AlertEngine::new(state.clone(), bus_rx);
        tokio::spawn(async move { engine.run().await });
    }

    // Spawn transport run loop.
    let transport = Arc::new(transport);
    {
        let t = transport.clone();
        tokio::spawn(async move { t.run().await });
    }

    // Push a startup log entry.
    state.push_log(
        LogEntry::new(
            LogLevel::Ok,
            format!("AITP server started — listening on 0.0.0.0:{}", cli.port),
        )
        .with_meta("mode", &cli.trust_mode)
        .with_meta("dev", cli.dev_mode.to_string()),
    );

    // Event bridge: route transport events → ServerState.
    let state_bridge = state.clone();
    tokio::spawn(async move {
        while let Some(ev) = event_rx.recv().await {
            match ev {
                TransportEvent::SessionEstablished {
                    session_id,
                    peer_addr,
                    peer_entity_id,
                    intent,
                    trust_score,
                } => {
                    let client = ConnectedClient {
                        session_id,
                        entity_id: peer_entity_id,
                        display_name: format!("client-{}", &hex_encode(&peer_entity_id)[..6]),
                        peer_addr,
                        trust_score,
                        intent,
                        connected_at: Utc::now(),
                        packets_received: 0,
                        bytes_received: 0,
                    };
                    state_bridge.add_client(client);
                }
                TransportEvent::SessionClosed { session_id, .. }
                | TransportEvent::SessionRevoked { session_id, .. } => {
                    state_bridge.remove_client(session_id);
                }
                TransportEvent::DataReceived {
                    session_id,
                    payload,
                    ..
                } => {
                    let bytes = payload.len();
                    if let Some(mut c) = state_bridge.clients.get_mut(&session_id) {
                        c.packets_received += 1;
                        c.bytes_received += bytes as u64;
                    }
                }
                TransportEvent::PacketDropped { peer_addr, reason } => {
                    state_bridge
                        .stats
                        .blocked_packets
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let msg = format!("AITP_DROP({}) from {}", reason, peer_addr);
                    state_bridge.push_log(LogEntry::new(LogLevel::Warn, msg));
                }
                TransportEvent::HandshakeRejected {
                    peer_addr, reason, ..
                } => {
                    let msg = format!("Handshake REJECTED from {}: {}", peer_addr, reason);
                    state_bridge.push_log(LogEntry::new(LogLevel::Alert, msg));
                }
            }
        }
    });

    if use_tui {
        run_tui(state, &identity_hex, &cli).await?;
    } else {
        run_json_logs(state, &cli).await?;
    }

    Ok(())
}

// ────────────────────────── TUI mode ──────────────────────────

async fn run_tui(state: Arc<ServerState>, identity_hex: &str, cli: &Cli) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let listen_addr = format!("0.0.0.0:{}", cli.port);
    let mode = if cli.dev_mode {
        "DEV MODE"
    } else {
        &cli.trust_mode
    };
    let ebpf_active = !cli.dev_mode && cfg!(target_os = "linux");

    let tick = Duration::from_millis(100); // 10 FPS
    loop {
        tui::draw(
            &mut terminal,
            &state,
            &listen_addr,
            identity_hex,
            mode,
            ebpf_active,
        )?;

        // Poll for input without blocking.
        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    println!("{}", "AITP server stopped.".dimmed());
    Ok(())
}

// ────────────────────────── JSON log mode (non-TTY / Docker) ──────────────────────────

async fn run_json_logs(state: Arc<ServerState>, cli: &Cli) -> anyhow::Result<()> {
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "server_started",
            "port": cli.port,
            "trust_mode": cli.trust_mode,
            "dev_mode": cli.dev_mode,
        })
    );

    // Poll the rolling log and print new entries as JSON lines.
    let mut last_len = 0usize;
    loop {
        {
            let log = state.log.read().unwrap();
            let entries: Vec<_> = log.iter().skip(last_len).collect();
            for entry in &entries {
                let json = serde_json::json!({
                    "timestamp": entry.timestamp.to_rfc3339(),
                    "level": format!("{:?}", entry.level),
                    "message": entry.message,
                    "metadata": entry.metadata,
                });
                println!("{json}");
            }
            last_len += entries.len();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ────────────────────────── Helpers ──────────────────────────

fn load_or_generate_identity(_path: &PathBuf) -> anyhow::Result<AitpIdentity> {
    // For dev purposes: always generate a fresh identity.
    // In production this would load from disk or a secrets manager.
    let identity = AitpIdentity::generate(
        "aitp-server".to_string(),
        EntityType::Service,
        vec![Capability::Inference, Capability::Coordination],
    );
    tracing::info!(
        entity_id = hex_encode(&identity.entity_id),
        "Identity loaded (generated)"
    );
    Ok(identity)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
