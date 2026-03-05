//! AITP Node — Runnable binary for the Adaptive Intent Transport Protocol.
//!
//! This binary is the primary entry point for running an AITP node.
//! It handles:
//! - TOML configuration loading
//! - Ed25519 identity loading or generation
//! - UDP transport loop with packet routing
//! - Full handshake execution for inbound and outbound connections
//! - Graceful shutdown on SIGTERM/SIGINT
//!
//! # Usage
//!
//! ```bash
//! # Listen mode (accept incoming connections)
//! aitp-node --config aitp.toml --mode listen
//!
//! # Connect mode (initiate a connection to a peer)
//! aitp-node --config aitp.toml --mode connect --peer <entity_id_hex>@<ip:port>
//! ```

use aitp_core::config::AitpConfig;
use aitp_core::framing::AitpPacket;
use aitp_core::handshake::HandshakeState;
use aitp_core::header::{flags, AitpHeader, IntentCode};
use aitp_core::session::{Session, SessionTable};
use aitp_core::transport::{AitpTransport, PacketAction, TransportConfig};

use aitp_ai_engine::engine::{TrustContext, TrustEngine};
use aitp_ai_engine::scorer::Verdict;
use aitp_identity::identity::{AitpIdentity, Capability, EntityType};

use clap::Parser;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;

// ────────────────────────── CLI ──────────────────────────

/// AITP Node — Adaptive Intent Transport Protocol
#[derive(Parser, Debug)]
#[command(name = "aitp-node", version, about = "Run an AITP protocol node")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "aitp.toml")]
    config: PathBuf,

    /// Operating mode: "listen" or "connect".
    #[arg(short, long, default_value = "listen")]
    mode: String,

    /// Peer to connect to (connect mode only).
    /// Format: <entity_id_hex>@<ip:port>
    #[arg(short, long)]
    peer: Option<String>,

    /// Generate a default config file and exit.
    #[arg(long)]
    init_config: bool,
}

/// Parsed peer address from CLI.
#[derive(Debug, Clone)]
struct PeerAddr {
    entity_id_hex: String,
    addr: SocketAddr,
}

impl PeerAddr {
    fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.splitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(format!(
                "invalid peer format: expected <entity_id>@<ip:port>, got: {s}"
            ));
        }
        let addr: SocketAddr = parts[1]
            .parse()
            .map_err(|e| format!("invalid peer address '{}': {e}", parts[1]))?;
        Ok(Self {
            entity_id_hex: parts[0].to_string(),
            addr,
        })
    }
}

// ────────────────────────── Main ──────────────────────────

#[tokio::main]
async fn main() {
    // Catch panics and log them
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        eprintln!("FATAL PANIC: {msg}");
        if let Some(loc) = info.location() {
            eprintln!("  at {}:{}:{}", loc.file(), loc.line(), loc.column());
        }
        default_hook(info);
    }));

    let cli = Cli::parse();

    // Handle --init-config: generate default config and exit
    if cli.init_config {
        let config = AitpConfig::default();
        match config.to_toml_string() {
            Ok(toml_str) => {
                let path = &cli.config;
                if let Err(e) = std::fs::write(path, &toml_str) {
                    eprintln!("ERROR: Failed to write config to {}: {e}", path.display());
                    std::process::exit(1);
                }
                println!("Config written to {}", path.display());
                println!("{toml_str}");
            }
            Err(e) => {
                eprintln!("ERROR: Failed to serialize config: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Load config
    let config = if cli.config.exists() {
        match AitpConfig::from_file(&cli.config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("ERROR: {e}");
                eprintln!("Run with --init-config to generate a default config file.");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!(
            "WARN: Config file '{}' not found, using defaults.",
            cli.config.display()
        );
        AitpConfig::default()
    };

    // Initialize tracing
    let json_log = config.node.log_format == "json";
    init_tracing(&config.node.log_level, json_log);

    let listen_addr = match config.listen_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ERROR: invalid listen address: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!(
        name = %config.node.name,
        mode = %cli.mode,
        bind_addr = %listen_addr,
        "Starting AITP node"
    );

    // Load or generate identity
    let identity = load_or_generate_identity(&config);
    let entity_id_hex = hex_encode(&identity.entity_id);

    emit_event(
        "node.started",
        serde_json::json!({
            "name": config.node.name,
            "entity_id": entity_id_hex,
            "entity_type": config.node.entity_type,
            "bind_addr": listen_addr.to_string(),
            "mode": cli.mode,
        }),
    );

    // Create trust engine
    let trust_engine = Arc::new(TrustEngine::with_defaults());

    // Create transport config
    // In connect mode, use an ephemeral port (0) to avoid clashing
    // with a listener already bound to the configured port.
    let bind_addr = if cli.mode == "connect" {
        let mut addr = listen_addr;
        addr.set_port(0); // OS assigns a random available port
        addr
    } else {
        listen_addr
    };

    let transport_config = TransportConfig {
        bind_addr,
        max_sessions: config.transport.max_concurrent_sessions,
        max_datagram_size: config.transport.max_packet_size_bytes,
    };

    // Bind transport
    let transport = match AitpTransport::bind(transport_config).await {
        Ok(t) => Arc::new(t),
        Err(e) => {
            tracing::error!(error = %e, "Failed to bind UDP transport");
            std::process::exit(1);
        }
    };

    let local_addr = transport.local_addr().unwrap();
    tracing::info!(addr = %local_addr, "AITP transport bound");

    // Shutdown signal
    let shutdown = Arc::new(Notify::new());

    // Spawn control plane heartbeat task
    let cp_shutdown = shutdown.clone();
    let cp_heartbeat_secs = config.control_plane.heartbeat_interval_secs;
    let cp_entity_id = entity_id_hex.clone();
    let cp_name = config.node.name.clone();
    tokio::spawn(async move {
        control_plane_heartbeat(cp_heartbeat_secs, cp_entity_id, cp_name, cp_shutdown).await;
    });

    // Run based on mode
    match cli.mode.as_str() {
        "listen" => {
            tracing::info!("Running in LISTEN mode — waiting for incoming connections");
            run_listener(
                transport,
                Arc::new(identity),
                trust_engine,
                shutdown.clone(),
            )
            .await;
        }
        "connect" => {
            let peer_str = cli.peer.unwrap_or_else(|| {
                tracing::error!("--peer is required in connect mode");
                std::process::exit(1);
            });
            let peer = PeerAddr::parse(&peer_str).unwrap_or_else(|e| {
                tracing::error!(error = %e, "Invalid peer address");
                std::process::exit(1);
            });
            tracing::info!(
                peer_id = %peer.entity_id_hex,
                peer_addr = %peer.addr,
                "Running in CONNECT mode"
            );
            run_connector(
                transport,
                Arc::new(identity),
                trust_engine,
                peer,
                shutdown.clone(),
            )
            .await;
        }
        other => {
            tracing::error!(mode = %other, "Unknown mode. Use 'listen' or 'connect'.");
            std::process::exit(1);
        }
    }
}

// ────────────────────────── Listener Mode ──────────────────────────

/// Run the node in listen mode: accept incoming connections.
async fn run_listener(
    transport: Arc<AitpTransport>,
    identity: Arc<AitpIdentity>,
    trust_engine: Arc<TrustEngine>,
    shutdown: Arc<Notify>,
) {
    let session_table = SessionTable::new(65536);

    loop {
        tokio::select! {
            // Graceful shutdown
            _ = tokio::signal::ctrl_c() => {
                emit_event("node.shutdown", serde_json::json!({"reason": "SIGINT"}));
                shutdown.notify_waiters();
                break;
            }
            // Receive packets
            result = transport.recv_packet() => {
                match result {
                    Ok(PacketAction::NewSession { header, payload, peer_addr }) => {
                        let session_id = header.session_id;
                        emit_event("session.incoming", serde_json::json!({
                            "session_id": format!("{:#018x}", session_id),
                            "source_id": hex_encode(&header.source_id),
                            "intent": header.intent_code.as_str(),
                            "peer_addr": peer_addr.to_string(),
                        }));

                        // Perform server-side handshake
                        handle_incoming_session(
                            transport.clone(),
                            identity.clone(),
                            trust_engine.clone(),
                            &session_table,
                            header,
                            payload,
                            peer_addr,
                        )
                        .await;
                    }
                    Ok(PacketAction::RouteToSession { session_id, header, payload, peer_addr }) => {
                        // Route to existing session
                        if let Some(mut session) = session_table.get_mut(session_id) {
                            session.record_received(payload.len());

                            emit_event("session.data_received", serde_json::json!({
                                "session_id": format!("{:#018x}", session_id),
                                "payload_len": payload.len(),
                                "trust_score": header.trust_score,
                                "peer_addr": peer_addr.to_string(),
                            }));

                            // Echo the payload back as acknowledgement
                            if !payload.is_empty() {
                                if let Ok(payload_str) = String::from_utf8(payload.clone()) {
                                    tracing::info!(
                                        session_id = format!("{:#018x}", session_id),
                                        payload = %payload_str,
                                        "Received data"
                                    );
                                }

                                let response = format!("ACK: {} bytes received", payload.len());
                                let resp_header = build_data_header(
                                    &identity,
                                    session_id,
                                    &header.source_id,
                                    response.len() as u16,
                                );
                                if let Ok(pkt) = AitpPacket::new(resp_header, response.into_bytes()) {
                                    let _ = transport.send_packet(&pkt, peer_addr).await;
                                    session.record_sent(pkt.payload.len());
                                }
                            }
                        }
                    }
                    Ok(PacketAction::Dropped { reason }) => {
                        tracing::debug!(reason = %reason, "Packet dropped");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Transport receive error");
                    }
                }
            }
        }
    }
}

/// Handle an incoming SYN: run the server-side handshake.
async fn handle_incoming_session(
    transport: Arc<AitpTransport>,
    identity: Arc<AitpIdentity>,
    trust_engine: Arc<TrustEngine>,
    session_table: &SessionTable,
    syn_header: AitpHeader,
    _payload: Vec<u8>,
    peer_addr: SocketAddr,
) {
    let session_id = syn_header.session_id;
    let source_id = syn_header.source_id;

    // Create session
    let mut session = Session::new(
        session_id,
        identity.entity_id,
        source_id,
        syn_header.intent_code,
    );

    // Run trust evaluation
    let trust_ctx = TrustContext {
        source_entity_id: source_id,
        dest_entity_id: identity.entity_id,
        intent_code: syn_header.intent_code as u16,
        identity_age_secs: 3600, // Unknown peer, use default
        historical_score: None,
        behavioral_flags: vec![],
        time_of_day: current_hour(),
        session_frequency: 1,
    };

    let decision = trust_engine.evaluate(&trust_ctx);

    emit_event(
        "trust.evaluated",
        serde_json::json!({
            "session_id": format!("{:#018x}", session_id),
            "verdict": format!("{:?}", decision.verdict),
            "trust_score": decision.trust_score,
            "reason": format!("{:?}", decision.reason_code),
            "eval_time_ms": decision.eval_time_ns as f64 / 1_000_000.0,
        }),
    );

    if decision.verdict == Verdict::Deny {
        tracing::warn!(
            session_id = format!("{:#018x}", session_id),
            score = decision.trust_score,
            "Connection DENIED by trust engine"
        );
        // Send REVOKE
        let revoke = build_revoke_header(&identity, session_id, &source_id);
        if let Ok(pkt) = AitpPacket::new(revoke, vec![]) {
            let _ = transport.send_packet(&pkt, peer_addr).await;
        }
        return;
    }

    // Send SYN+ACK (identity exchange + session grant)
    session.trust_score = decision.trust_score;
    session.state = HandshakeState::SessionActive;

    let syn_ack = build_syn_ack_header(&identity, session_id, &source_id, decision.trust_score);

    if let Ok(pkt) = AitpPacket::new(syn_ack, vec![]) {
        if let Err(e) = transport.send_packet(&pkt, peer_addr).await {
            tracing::error!(error = %e, "Failed to send SYN+ACK");
            return;
        }
    }

    // Insert session into table
    if let Err(e) = session_table.insert(session) {
        tracing::error!(error = %e, "Failed to insert session");
        return;
    }

    emit_event(
        "session.established",
        serde_json::json!({
            "session_id": format!("{:#018x}", session_id),
            "source_id": hex_encode(&source_id),
            "intent": syn_header.intent_code.as_str(),
            "trust_score": decision.trust_score,
            "peer_addr": peer_addr.to_string(),
        }),
    );
}

// ────────────────────────── Connector Mode ──────────────────────────

/// Run the node in connect mode: initiate an outbound connection.
async fn run_connector(
    transport: Arc<AitpTransport>,
    identity: Arc<AitpIdentity>,
    _trust_engine: Arc<TrustEngine>,
    peer: PeerAddr,
    shutdown: Arc<Notify>,
) {
    let session_id: u64 = rand::random();
    let dest_id = hex_decode_32(&peer.entity_id_hex).unwrap_or_else(|| {
        tracing::warn!("Could not decode peer entity ID, using hash of hex string");
        let hash: [u8; 32] = Sha256::digest(peer.entity_id_hex.as_bytes()).into();
        hash
    });

    emit_event(
        "session.connecting",
        serde_json::json!({
            "session_id": format!("{:#018x}", session_id),
            "peer_id": peer.entity_id_hex,
            "peer_addr": peer.addr.to_string(),
        }),
    );

    // Send SYN
    let syn_header = AitpHeader::new(
        flags::SYN,
        IntentCode::ModelInference,
        session_id,
        identity.entity_id,
        dest_id,
        0,
        0,
        now_nanos(),
        rand_nonce(),
    );

    let mut syn_header = syn_header;
    syn_header.sign(identity.signing_key());

    let syn_packet = AitpPacket::new(syn_header, vec![]).unwrap();
    if let Err(e) = transport.send_packet(&syn_packet, peer.addr).await {
        tracing::error!(error = %e, "Failed to send SYN");
        return;
    }

    emit_event(
        "handshake.syn_sent",
        serde_json::json!({
            "session_id": format!("{:#018x}", session_id),
        }),
    );

    // Wait for SYN+ACK
    let ack = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wait_for_response(&transport, session_id),
    )
    .await;

    match ack {
        Ok(Ok((header, _payload, _peer))) => {
            if header.is_revoke() {
                emit_event(
                    "session.rejected",
                    serde_json::json!({
                        "session_id": format!("{:#018x}", session_id),
                        "reason": "peer sent REVOKE",
                    }),
                );
                return;
            }

            emit_event(
                "handshake.syn_ack_received",
                serde_json::json!({
                    "session_id": format!("{:#018x}", session_id),
                    "trust_score": header.trust_score,
                }),
            );

            emit_event(
                "session.established",
                serde_json::json!({
                    "session_id": format!("{:#018x}", session_id),
                    "peer_id": peer.entity_id_hex,
                    "peer_addr": peer.addr.to_string(),
                    "trust_score": header.trust_score,
                }),
            );

            // Send test payload
            let test_data = b"Hello from AITP! This is a test payload.".to_vec();
            let data_header =
                build_data_header(&identity, session_id, &dest_id, test_data.len() as u16);
            let data_packet = AitpPacket::new(data_header, test_data).unwrap();
            if let Err(e) = transport.send_packet(&data_packet, peer.addr).await {
                tracing::error!(error = %e, "Failed to send test payload");
            } else {
                emit_event(
                    "session.data_sent",
                    serde_json::json!({
                        "session_id": format!("{:#018x}", session_id),
                        "payload": "Hello from AITP! This is a test payload.",
                        "payload_len": 40,
                    }),
                );
            }

            // Wait for ACK response
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                wait_for_response(&transport, session_id),
            )
            .await;

            if let Ok(Ok((_, payload, _))) = resp {
                if let Ok(text) = String::from_utf8(payload) {
                    emit_event(
                        "session.data_received",
                        serde_json::json!({
                            "session_id": format!("{:#018x}", session_id),
                            "response": text,
                        }),
                    );
                }
            }

            // Send FIN
            let fin_header = build_fin_header(&identity, session_id, &dest_id);
            let fin_packet = AitpPacket::new(fin_header, vec![]).unwrap();
            let _ = transport.send_packet(&fin_packet, peer.addr).await;

            emit_event(
                "session.closed",
                serde_json::json!({
                    "session_id": format!("{:#018x}", session_id),
                    "reason": "transfer complete",
                }),
            );
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to receive SYN+ACK");
        }
        Err(_) => {
            emit_event(
                "handshake.timeout",
                serde_json::json!({
                    "session_id": format!("{:#018x}", session_id),
                    "timeout_secs": 5,
                }),
            );
        }
    }

    shutdown.notify_waiters();
}

/// Wait for a response packet matching our session ID.
async fn wait_for_response(
    transport: &AitpTransport,
    session_id: u64,
) -> Result<(AitpHeader, Vec<u8>, SocketAddr), String> {
    loop {
        match transport.recv_packet().await {
            Ok(PacketAction::NewSession {
                header,
                payload,
                peer_addr,
            })
            | Ok(PacketAction::RouteToSession {
                header,
                payload,
                peer_addr,
                ..
            }) => {
                if header.session_id == session_id {
                    return Ok((header, payload, peer_addr));
                }
            }
            Ok(PacketAction::Dropped { reason }) => {
                tracing::debug!(reason = %reason, "Dropped irrelevant packet while waiting");
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

// ────────────────────────── Control Plane Heartbeat ──────────────────────────

async fn control_plane_heartbeat(
    heartbeat_interval_secs: u64,
    entity_id_hex: String,
    name: String,
    shutdown: Arc<Notify>,
) {
    let interval = std::time::Duration::from_secs(heartbeat_interval_secs);

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("Control plane heartbeat task shutting down");
                break;
            }
            _ = tokio::time::sleep(interval) => {
                tracing::debug!(
                    entity_id = %entity_id_hex,
                    name = %name,
                    "Control plane heartbeat"
                );
            }
        }
    }
}

// ────────────────────────── Identity Persistence ──────────────────────────

/// Load an Ed25519 identity from disk, or generate a new one.
fn load_or_generate_identity(config: &AitpConfig) -> AitpIdentity {
    let key_path = &config.node.identity_key_path;
    let entity_type = match config.node.entity_type.as_str() {
        "Human" => EntityType::Human,
        "AiModel" => EntityType::AiModel,
        "Device" => EntityType::Device,
        _ => EntityType::Service,
    };

    if key_path.exists() {
        match std::fs::read(key_path) {
            Ok(bytes) if bytes.len() == 32 => {
                let key_bytes: [u8; 32] = bytes.try_into().unwrap();
                let signing_key = SigningKey::from_bytes(&key_bytes);
                let identity = AitpIdentity::from_signing_key(
                    signing_key,
                    &config.node.name,
                    entity_type,
                    vec![Capability::Inference, Capability::Coordination],
                );
                tracing::info!(
                    entity_id = %hex_encode(&identity.entity_id),
                    key_path = %key_path.display(),
                    "Loaded identity from disk"
                );
                identity
            }
            Ok(bytes) => {
                tracing::warn!(
                    size = bytes.len(),
                    expected = 32,
                    "Key file has wrong size, generating new identity"
                );
                generate_and_save_identity(config, entity_type)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read key file, generating new identity");
                generate_and_save_identity(config, entity_type)
            }
        }
    } else {
        generate_and_save_identity(config, entity_type)
    }
}

fn generate_and_save_identity(config: &AitpConfig, entity_type: EntityType) -> AitpIdentity {
    let identity = AitpIdentity::generate(
        &config.node.name,
        entity_type,
        vec![Capability::Inference, Capability::Coordination],
    );

    // Save private key to disk
    let key_bytes = identity.signing_key().to_bytes();
    if let Some(parent) = config.node.identity_key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&config.node.identity_key_path, key_bytes) {
        Ok(_) => {
            tracing::info!(
                entity_id = %hex_encode(&identity.entity_id),
                key_path = %config.node.identity_key_path.display(),
                "Generated and saved new identity"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Failed to save key to disk (identity is ephemeral)"
            );
        }
    }

    identity
}

// ────────────────────────── Header Builders ──────────────────────────

fn build_syn_ack_header(
    identity: &AitpIdentity,
    session_id: u64,
    dest_id: &[u8; 32],
    trust_score: u8,
) -> AitpHeader {
    let mut header = AitpHeader::new(
        flags::SYN | flags::ACK,
        IntentCode::ControlSignal,
        session_id,
        identity.entity_id,
        *dest_id,
        trust_score,
        0,
        now_nanos(),
        rand_nonce(),
    );
    header.sign(identity.signing_key());
    header
}

fn build_data_header(
    identity: &AitpIdentity,
    session_id: u64,
    dest_id: &[u8; 32],
    payload_len: u16,
) -> AitpHeader {
    let mut header = AitpHeader::new(
        0, // No flags for data
        IntentCode::DataSync,
        session_id,
        identity.entity_id,
        *dest_id,
        0,
        payload_len,
        now_nanos(),
        rand_nonce(),
    );
    header.sign(identity.signing_key());
    header
}

fn build_revoke_header(identity: &AitpIdentity, session_id: u64, dest_id: &[u8; 32]) -> AitpHeader {
    let mut header = AitpHeader::new(
        flags::REVOKE,
        IntentCode::ControlSignal,
        session_id,
        identity.entity_id,
        *dest_id,
        0,
        0,
        now_nanos(),
        rand_nonce(),
    );
    header.sign(identity.signing_key());
    header
}

fn build_fin_header(identity: &AitpIdentity, session_id: u64, dest_id: &[u8; 32]) -> AitpHeader {
    let mut header = AitpHeader::new(
        flags::FIN,
        IntentCode::ControlSignal,
        session_id,
        identity.entity_id,
        *dest_id,
        0,
        0,
        now_nanos(),
        rand_nonce(),
    );
    header.sign(identity.signing_key());
    header
}

// ────────────────────────── Tracing Init ──────────────────────────

fn init_tracing(level: &str, json: bool) {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    if json {
        fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(false)
            .init();
    } else {
        fmt().with_env_filter(filter).with_target(true).init();
    }
}

// ────────────────────────── Utilities ──────────────────────────

/// Emit a structured JSON event to stdout.
fn emit_event(event: &str, data: serde_json::Value) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let output = serde_json::json!({
        "timestamp": format!("{}.{:09}", ts.as_secs(), ts.subsec_nanos()),
        "event": event,
        "data": data,
    });

    println!("{}", serde_json::to_string(&output).unwrap_or_default());
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn rand_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn current_hour() -> u8 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ((secs % 86400) / 3600) as u8
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return None;
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Generate a default `aitp.toml` template.
fn _default_toml_template() -> &'static str {
    r#"# AITP Node Configuration

[identity]
name = "aitp-node"
key_path = "./aitp-node.key"
entity_type = "Service"

[transport]
bind_addr = "0.0.0.0:9999"
max_sessions = 65536
max_datagram_size = 65535

[trust]
min_identity_age_secs = 86400
eval_timeout_ms = 5

[control_plane]
url = "http://127.0.0.1:8080"
heartbeat_interval_secs = 30
auto_register = true

[logging]
level = "info"
json = true
"#
}
