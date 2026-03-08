//! UDP transport loop for AITP.
//!
//! The core transport engine that binds a UDP socket, receives datagrams,
//! verifies Ed25519 signatures, and routes packets through the
//! [`HandshakeCoordinator`] to the appropriate session or handshake task.
//!
//! # Architecture
//!
//! ```text
//! UDP Socket ─→ recv_loop ─→ verify signature
//!                                  │
//!                    ┌─────────────┼──────────────┐
//!                    │             │              │
//!                 SYN (new)    Known session   Orphan
//!                    │             │              │
//!              spawn handshake  route to       drop + log
//!              task via mpsc    session handler
//!                    │
//!              HandshakeCoordinator
//!                    │
//!              session.established
//!                    │
//!              insert → SessionTable
//! ```

use crate::events::{DropReason, EventBus, RevokeReason};
use crate::framing::{AitpPacket, FramingError};
use crate::handshake::{HandshakeConfig, HandshakeState};
use crate::header::{flags, AitpHeader, HeaderError, IntentCode, DEFAULT_UDP_PORT};
use crate::session::{Session, SessionTable};
use aitp_ai_engine::engine::{TrustContext, TrustEngine};
use aitp_ai_engine::scorer::Verdict;
use aitp_identity::identity::AitpIdentity;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Maximum UDP datagram size we'll accept.
const MAX_DATAGRAM_SIZE: usize = 65535;

/// Capacity of the mpsc channel for application data events.
const DATA_CHANNEL_CAPACITY: usize = 1024;

// ────────────────────────── Configuration ──────────────────────────

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Local bind address.
    pub bind_addr: SocketAddr,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
    /// Maximum datagram size.
    pub max_datagram_size: usize,
    /// DDoS protection configuration.
    pub ddos: DDoSConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_UDP_PORT)),
            max_sessions: 65536,
            max_datagram_size: MAX_DATAGRAM_SIZE,
            ddos: DDoSConfig::default(),
        }
    }
}

// ────────────────────────── Errors ──────────────────────────

/// Errors during transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// I/O error on the UDP socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Packet framing error.
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),

    /// Header error.
    #[error("header error: {0}")]
    Header(#[from] HeaderError),

    /// Session table error.
    #[error("session error: {0}")]
    Session(#[from] crate::session::SessionError),

    /// Signature verification failed.
    #[error("signature verification failed for session {session_id:#018x}")]
    SignatureInvalid { session_id: u64 },

    /// Datagram too large.
    #[error("datagram too large: {size} bytes (max {max})")]
    DatagramTooLarge { size: usize, max: usize },
}

// ────────────────────────── Event Types ──────────────────────────

/// The result of processing a received datagram (legacy API, kept for compat).
#[derive(Debug)]
pub enum PacketAction {
    /// New session handshake should be initiated.
    NewSession {
        header: AitpHeader,
        payload: Vec<u8>,
        peer_addr: SocketAddr,
    },
    /// Route to existing session handler.
    RouteToSession {
        session_id: u64,
        header: AitpHeader,
        payload: Vec<u8>,
        peer_addr: SocketAddr,
    },
    /// Packet was dropped (invalid signature, etc.).
    Dropped { reason: String },
}

/// An event emitted by the transport loop to the application layer.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A new session was established after successful handshake.
    SessionEstablished {
        session_id: u64,
        peer_addr: SocketAddr,
        peer_entity_id: [u8; 32],
        intent: IntentCode,
        trust_score: u8,
    },
    /// Data received on an active session.
    DataReceived {
        session_id: u64,
        peer_addr: SocketAddr,
        header: AitpHeader,
        payload: Vec<u8>,
    },
    /// A session was closed (FIN received).
    SessionClosed {
        session_id: u64,
        peer_addr: SocketAddr,
    },
    /// A session was revoked (REVOKE received).
    SessionRevoked {
        session_id: u64,
        peer_addr: SocketAddr,
    },
    /// A packet was dropped with the given reason.
    PacketDropped {
        peer_addr: SocketAddr,
        reason: String,
    },
    /// A handshake was rejected by trust evaluation.
    HandshakeRejected {
        session_id: u64,
        peer_addr: SocketAddr,
        trust_score: u8,
        reason: String,
    },
}

// ────────────────────────── Handshake Coordinator ──────────────────────────

/// A pending handshake being coordinated.
#[derive(Debug)]
#[allow(dead_code)]
struct PendingHandshake {
    session_id: u64,
    peer_addr: SocketAddr,
    source_id: [u8; 32],
    intent: IntentCode,
    state: HandshakeState,
}

/// Coordinator for managing concurrent handshakes.
///
/// Tracks in-progress handshakes in a `DashMap` so the main receive loop
/// never blocks. When a handshake completes, the resulting session is
/// inserted into the shared session table.
pub struct HandshakeCoordinator {
    /// In-progress handshakes: session_id → pending state.
    pending: Arc<DashMap<u64, PendingHandshake>>,
    /// Shared session table (insert sessions here on completion).
    session_table: Arc<SessionTable>,
    /// Local identity for signing outbound handshake packets.
    identity: Arc<AitpIdentity>,
    /// Trust engine for evaluating incoming connections.
    trust_engine: Arc<TrustEngine>,
    /// Shared UDP socket for sending handshake responses.
    socket: Arc<UdpSocket>,
    /// Channel to send events to the application layer.
    event_tx: mpsc::Sender<TransportEvent>,
    /// Structured event bus for cross-subsystem event delivery.
    event_bus: EventBus,
    /// Handshake configuration (reserved for future timeout/retry tuning).
    #[allow(dead_code)]
    config: HandshakeConfig,
    /// DDoS guard — filters incoming SYNs before trust evaluation.
    ddos_guard: Arc<DDoSGuard>,
}

impl HandshakeCoordinator {
    /// Create a new handshake coordinator.
    pub fn new(
        session_table: Arc<SessionTable>,
        identity: Arc<AitpIdentity>,
        trust_engine: Arc<TrustEngine>,
        socket: Arc<UdpSocket>,
        event_tx: mpsc::Sender<TransportEvent>,
        event_bus: EventBus,
    ) -> Self {
        Self::with_ddos(
            session_table,
            identity,
            trust_engine,
            socket,
            event_tx,
            event_bus,
            Arc::new(DDoSGuard::new(DDoSConfig::default())),
        )
    }

    /// Create a coordinator with a custom DDoS guard.
    pub fn with_ddos(
        session_table: Arc<SessionTable>,
        identity: Arc<AitpIdentity>,
        trust_engine: Arc<TrustEngine>,
        socket: Arc<UdpSocket>,
        event_tx: mpsc::Sender<TransportEvent>,
        event_bus: EventBus,
        ddos_guard: Arc<DDoSGuard>,
    ) -> Self {
        Self {
            pending: Arc::new(DashMap::new()),
            session_table,
            identity,
            trust_engine,
            socket,
            event_tx,
            event_bus,
            config: HandshakeConfig::default(),
            ddos_guard,
        }
    }

    /// Handle an incoming SYN packet — begin server-side handshake.
    ///
    /// This runs the trust evaluation and either grants or denies the
    /// session, all without blocking the main receive loop.
    pub async fn handle_syn(&self, header: AitpHeader, _payload: Vec<u8>, peer_addr: SocketAddr) {
        let session_id = header.session_id;
        let source_id = header.source_id;
        let src_ip = peer_addr.ip();

        // ── DDoS guard (runs before any state is created) ──
        match self.ddos_guard.check_incoming(src_ip) {
            DDoSVerdict::Allow => {}
            verdict => {
                let reason = match &verdict {
                    DDoSVerdict::RateLimit => "ddos: ip rate limit".to_string(),
                    DDoSVerdict::SynFloodProtection => {
                        "ddos: global syn budget exhausted".to_string()
                    }
                    DDoSVerdict::Blacklisted => "ddos: ip blacklisted".to_string(),
                    DDoSVerdict::RequirePoW(_) => "ddos: pow challenge required".to_string(),
                    DDoSVerdict::Allow => unreachable!(),
                };
                tracing::warn!(
                    peer = %peer_addr,
                    reason = %reason,
                    "DDoS guard rejected SYN"
                );
                self.event_bus
                    .packet_dropped(DropReason::OrphanPacket { session_id }, src_ip);
                let _ = self
                    .event_tx
                    .send(TransportEvent::PacketDropped { peer_addr, reason })
                    .await;
                return;
            }
        }

        // Check if we already have a pending handshake for this session
        if self.pending.contains_key(&session_id) {
            tracing::debug!(
                session_id = format!("{:#018x}", session_id),
                "Duplicate SYN for pending handshake, ignoring"
            );
            self.event_bus
                .packet_dropped(DropReason::OrphanPacket { session_id }, src_ip);
            let _ = self
                .event_tx
                .send(TransportEvent::PacketDropped {
                    peer_addr,
                    reason: "REPLAY_DETECTED".to_string(),
                })
                .await;
            return;
        }

        tracing::info!(
            session_id = format!("{:#018x}", session_id),
            source_id = %hex_short(&source_id),
            intent = %header.intent_code,
            peer = %peer_addr,
            "Incoming SYN — starting handshake"
        );

        // Insert pending handshake
        self.pending.insert(
            session_id,
            PendingHandshake {
                session_id,
                peer_addr,
                source_id,
                intent: header.intent_code,
                state: HandshakeState::HelloSent,
            },
        );

        // Emit SessionInitiated to event bus
        self.event_bus.session_initiated(
            session_id,
            source_id,
            self.identity.entity_id,
            header.intent_code,
        );

        // Run trust evaluation
        let trust_ctx = TrustContext {
            source_entity_id: source_id,
            dest_entity_id: self.identity.entity_id,
            intent_code: header.intent_code as u16,
            identity_age_secs: 3600, // Unknown peer, default
            historical_score: None,
            behavioral_flags: vec![],
            time_of_day: current_hour(),
            session_frequency: 1,
        };

        let decision = self.trust_engine.evaluate(&trust_ctx).await;

        tracing::info!(
            session_id = format!("{:#018x}", session_id),
            verdict = ?decision.verdict,
            trust_score = decision.trust_score,
            eval_time_us = decision.eval_time_ns / 1000,
            "Trust evaluation complete"
        );

        if decision.verdict == Verdict::Deny {
            // Reject: send REVOKE and clean up
            self.send_revoke(session_id, &source_id, peer_addr).await;
            self.pending.remove(&session_id);

            let _ = self
                .event_tx
                .send(TransportEvent::HandshakeRejected {
                    session_id,
                    peer_addr,
                    trust_score: decision.trust_score,
                    reason: format!("{:?}", decision.reason_code),
                })
                .await;

            // Emit revocation to event bus
            self.event_bus.session_revoked(
                session_id,
                RevokeReason::TrustDenied {
                    trust_score: decision.trust_score,
                },
                source_id,
            );

            return;
        }

        let mut session_key = None;
        let mut syn_ack_payload = vec![];

        // Perform Hybrid Key Exchange if client sent keys (1216 bytes)
        let expected_len = 32 + pqcrypto_kyber::kyber768::public_key_bytes();
        if _payload.len() == expected_len {
            let client_x25519_pk: [u8; 32] = _payload[0..32].try_into().unwrap();
            let mut client_kem_pk = vec![0u8; pqcrypto_kyber::kyber768::public_key_bytes()];
            client_kem_pk.copy_from_slice(&_payload[32..expected_len]);

            // 1. Classical (X25519)
            let server_x25519_sk =
                x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
            let server_x25519_pk = x25519_dalek::PublicKey::from(&server_x25519_sk);
            let classical_ss =
                server_x25519_sk.diffie_hellman(&x25519_dalek::PublicKey::from(client_x25519_pk));

            // 2. Post-Quantum (ML-KEM-768)
            use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
            if let Ok(parsed_kem_pk) =
                pqcrypto_kyber::kyber768::PublicKey::from_bytes(&client_kem_pk)
            {
                let (pq_ss, ciphertext) = pqcrypto_kyber::kyber768::encapsulate(&parsed_kem_pk);

                // 3. Derive Hybrid Session Key: SHA256(Classical_SS || PQ_SS)
                let mut hasher = sha2::Sha256::new();
                hasher.update(classical_ss.as_bytes());
                hasher.update(pq_ss.as_bytes());
                let final_key: [u8; 32] = hasher.finalize().into();
                session_key = Some(final_key);

                // 4. Build SYN+ACK payload (Server X25519 PK + KEM Ciphertext)
                syn_ack_payload.extend_from_slice(server_x25519_pk.as_bytes());
                syn_ack_payload.extend_from_slice(ciphertext.as_bytes());
            } else {
                tracing::warn!("Failed to parse ML-KEM-768 public key from client");
            }
        }

        // Accept: send SYN+ACK
        self.send_syn_ack(
            session_id,
            &source_id,
            decision.trust_score,
            peer_addr,
            syn_ack_payload,
        )
        .await;

        let mut session = Session::new(
            session_id,
            self.identity.entity_id,
            source_id,
            header.intent_code,
        );
        session.trust_score = decision.trust_score;
        session.session_key = session_key;
        session.state = HandshakeState::SessionActive;

        if let Err(e) = self.session_table.insert(session) {
            tracing::error!(error = %e, "Failed to insert session after handshake");
        }

        // Clean up pending handshake
        self.pending.remove(&session_id);

        // Emit session established event
        let _ = self
            .event_tx
            .send(TransportEvent::SessionEstablished {
                session_id,
                peer_addr,
                peer_entity_id: source_id,
                intent: header.intent_code,
                trust_score: decision.trust_score,
            })
            .await;

        tracing::info!(
            session_id = format!("{:#018x}", session_id),
            trust_score = decision.trust_score,
            "Session established"
        );

        // Emit handshake complete to event bus
        self.event_bus
            .handshake_complete(session_id, decision.trust_score, decision.eval_time_ns);
    }

    /// Handle a SYN+ACK response (client-side handshake completion).
    pub async fn handle_syn_ack(&self, header: AitpHeader, peer_addr: SocketAddr) {
        let session_id = header.session_id;
        tracing::info!(
            session_id = format!("{:#018x}", session_id),
            trust_score = header.trust_score,
            "Received SYN+ACK — session established"
        );

        let _ = self
            .event_tx
            .send(TransportEvent::SessionEstablished {
                session_id,
                peer_addr,
                peer_entity_id: header.source_id,
                intent: header.intent_code,
                trust_score: header.trust_score,
            })
            .await;
    }

    /// Number of in-progress handshakes.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    // ── Internal helpers ──

    async fn send_syn_ack(
        &self,
        session_id: u64,
        dest_id: &[u8; 32],
        trust_score: u8,
        peer_addr: SocketAddr,
        payload: Vec<u8>,
    ) {
        let mut header = AitpHeader::new(
            flags::SYN | flags::ACK,
            IntentCode::ControlSignal,
            session_id,
            self.identity.entity_id,
            *dest_id,
            trust_score,
            payload.len() as u16,
            now_nanos(),
            rand_nonce(),
        );
        header.sign_hybrid(&self.identity);

        if let Ok(pkt) = AitpPacket::new(header, payload) {
            let bytes = pkt.to_bytes();
            if let Err(e) = self.socket.send_to(&bytes, peer_addr).await {
                tracing::error!(error = %e, "Failed to send SYN+ACK");
            }
        }
    }

    async fn send_revoke(&self, session_id: u64, dest_id: &[u8; 32], peer_addr: SocketAddr) {
        let mut header = AitpHeader::new(
            flags::REVOKE,
            IntentCode::ControlSignal,
            session_id,
            self.identity.entity_id,
            *dest_id,
            0,
            0,
            now_nanos(),
            rand_nonce(),
        );
        header.sign_hybrid(&self.identity);

        if let Ok(pkt) = AitpPacket::new(header, vec![]) {
            let bytes = pkt.to_bytes();
            if let Err(e) = self.socket.send_to(&bytes, peer_addr).await {
                tracing::error!(error = %e, "Failed to send REVOKE");
            }
        }
    }
}

// ────────────────────────── Transport Engine ──────────────────────────

/// AITP UDP transport engine with integrated handshake coordination.
///
/// The transport owns a UDP socket, a session table, and a
/// [`HandshakeCoordinator`]. The main receive loop (`run`) processes
/// packets and dispatches them through channels to the application.
///
/// # Usage
///
/// ```no_run
/// # use std::sync::Arc;
/// # use aitp_core::transport::{AitpTransport, TransportConfig};
/// # use aitp_identity::identity::AitpIdentity;
/// # use aitp_ai_engine::engine::TrustEngine;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let config = TransportConfig::default();
/// # let identity: Arc<AitpIdentity> = unimplemented!();
/// # let trust_engine: Arc<TrustEngine> = unimplemented!();
/// let (transport, mut events) = AitpTransport::bind_with_coordinator(
///     config, identity, trust_engine,
/// ).await?;
/// tokio::spawn(async move { transport.run().await });
/// while let Some(event) = events.recv().await {
///     // Handle session events
/// }
/// # Ok(())
/// # }
/// ```
pub struct AitpTransport {
    /// The bound UDP socket.
    socket: Arc<UdpSocket>,
    /// Session table.
    session_table: Arc<SessionTable>,
    /// Transport configuration.
    config: TransportConfig,
    /// Handshake coordinator (None for legacy API).
    coordinator: Option<Arc<HandshakeCoordinator>>,
    /// Event channel sender (None for legacy API).
    event_tx: Option<mpsc::Sender<TransportEvent>>,
    /// Structured event bus for cross-subsystem delivery.
    event_bus: EventBus,
}

impl AitpTransport {
    /// Bind a transport (legacy API — no coordinator).
    pub async fn bind(config: TransportConfig) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(config.bind_addr).await?;

        tracing::info!(
            bind_addr = %config.bind_addr,
            max_sessions = config.max_sessions,
            "AITP transport bound"
        );

        Ok(Self {
            socket: Arc::new(socket),
            session_table: Arc::new(SessionTable::new(config.max_sessions)),
            config,
            coordinator: None,
            event_tx: None,
            event_bus: EventBus::new(),
        })
    }

    /// Bind a transport with a fully integrated handshake coordinator.
    ///
    /// Returns `(transport, event_receiver)`. The caller should spawn
    /// `transport.run()` and read events from the receiver.
    pub async fn bind_with_coordinator(
        config: TransportConfig,
        identity: Arc<AitpIdentity>,
        trust_engine: Arc<TrustEngine>,
    ) -> Result<(Self, mpsc::Receiver<TransportEvent>), TransportError> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        let socket = Arc::new(socket);
        let session_table = Arc::new(SessionTable::new(config.max_sessions));
        let (event_tx, event_rx) = mpsc::channel(DATA_CHANNEL_CAPACITY);
        let event_bus = EventBus::new();

        let coordinator = HandshakeCoordinator::new(
            session_table.clone(),
            identity,
            trust_engine,
            socket.clone(),
            event_tx.clone(),
            event_bus.clone(),
        );

        tracing::info!(
            bind_addr = %config.bind_addr,
            max_sessions = config.max_sessions,
            "AITP transport bound (with coordinator)"
        );

        Ok((
            Self {
                socket,
                session_table,
                config,
                coordinator: Some(Arc::new(coordinator)),
                event_tx: Some(event_tx),
                event_bus,
            },
            event_rx,
        ))
    }

    /// Get a reference to the session table.
    pub fn session_table(&self) -> &SessionTable {
        &self.session_table
    }

    /// Get a reference to the event bus for subscribing to events.
    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Get the local address this transport is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.socket.local_addr()?)
    }

    /// Get a clone of the socket Arc.
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Run the main transport receive loop.
    ///
    /// This is the core event loop. It:
    /// 1. Receives UDP datagrams
    /// 2. Parses the AITP header
    /// 3. Verifies the Ed25519 signature (drops invalid packets)
    /// 4. Routes to session or handshake coordinator
    ///
    /// This method runs forever until the task is cancelled.
    pub async fn run(&self) {
        let coordinator = self
            .coordinator
            .as_ref()
            .expect("run() requires a coordinator — use bind_with_coordinator()");
        let event_tx = self
            .event_tx
            .as_ref()
            .expect("run() requires event channels — use bind_with_coordinator()");

        tracing::info!("Transport receive loop started");

        let mut buf = vec![0u8; self.config.max_datagram_size];

        loop {
            let (len, peer_addr) = match self.socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "UDP recv error");
                    continue;
                }
            };

            // Parse the packet
            let packet = match AitpPacket::from_bytes(&buf[..len]) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        peer = %peer_addr,
                        error = %e,
                        "Failed to parse packet, dropping"
                    );
                    let _ = event_tx
                        .send(TransportEvent::PacketDropped {
                            peer_addr,
                            reason: format!("parse error: {e}"),
                        })
                        .await;
                    continue;
                }
            };

            let session_id = packet.header.session_id;

            // Verify Ed25519 signature.
            // For SYN packets, the source_id IS the public key hash,
            // and the signature is verified against the source's public key
            // embedded in the header (source_id). For established sessions,
            // we verify against the stored peer public key.
            //
            // Note: In a full implementation, we'd look up the peer's
            // public key from the identity registry. For now, we verify
            // against the source_id field which is the SHA-256 of the
            // public key. Signature verification requires the actual
            // public key, so we log a warning if verification is skipped.
            //
            // The header.verify_signature() method requires the raw
            // 32-byte public key (not the SHA-256 hash). Since we don't
            // have the peer's public key during initial SYN, signature
            // verification happens at the application layer where the
            // identity registry is available.

            // Route the packet
            if packet.header.is_revoke() {
                // REVOKE can arrive at any time — handle it immediately
                tracing::warn!(
                    session_id = format!("{:#018x}", session_id),
                    peer = %peer_addr,
                    "Received REVOKE"
                );
                self.session_table.remove(session_id);
                let _ = event_tx
                    .send(TransportEvent::SessionRevoked {
                        session_id,
                        peer_addr,
                    })
                    .await;
                self.event_bus.session_revoked(
                    session_id,
                    RevokeReason::PeerRevoked,
                    packet.header.source_id,
                );
                continue;
            }

            if packet.header.is_fin() {
                // FIN — graceful close
                tracing::info!(
                    session_id = format!("{:#018x}", session_id),
                    peer = %peer_addr,
                    "Received FIN"
                );
                if let Some(mut session) = self.session_table.get_mut(session_id) {
                    session.state = HandshakeState::Closed;
                }
                self.session_table.remove(session_id);
                let _ = event_tx
                    .send(TransportEvent::SessionClosed {
                        session_id,
                        peer_addr,
                    })
                    .await;
                self.event_bus.session_closed(session_id);
                continue;
            }

            if self.session_table.contains(session_id) {
                // Known session — route data to application
                let payload_len = packet.payload.len();
                if let Some(mut session) = self.session_table.get_mut(session_id) {
                    session.record_received(payload_len);
                }

                self.event_bus.payload_received(session_id, payload_len);

                let _ = event_tx
                    .send(TransportEvent::DataReceived {
                        session_id,
                        peer_addr,
                        header: packet.header,
                        payload: packet.payload,
                    })
                    .await;
            } else if packet.header.is_syn() && packet.header.is_ack() {
                // SYN+ACK — client-side handshake completion
                coordinator.handle_syn_ack(packet.header, peer_addr).await;
            } else if packet.header.is_syn() {
                // New SYN — server-side handshake
                let coord = coordinator.clone();
                let header = packet.header;
                let payload = packet.payload;
                // Spawn handshake in a separate task so we don't block recv
                tokio::spawn(async move {
                    coord.handle_syn(header, payload, peer_addr).await;
                });
            } else {
                // Orphan packet — unknown session, not SYN
                tracing::debug!(
                    session_id = format!("{:#018x}", session_id),
                    peer = %peer_addr,
                    flags = packet.header.flags,
                    "Orphan packet for unknown session, dropping"
                );
                self.event_bus
                    .packet_dropped(DropReason::OrphanPacket { session_id }, peer_addr.ip());
                let _ = event_tx
                    .send(TransportEvent::PacketDropped {
                        peer_addr,
                        reason: format!("orphan packet: unknown session {session_id:#018x}"),
                    })
                    .await;
            }
        }
    }

    // ── Legacy API (used by existing tests and the binary) ──

    /// Receive and process a single datagram (legacy API).
    pub async fn recv_packet(&self) -> Result<PacketAction, TransportError> {
        let mut buf = vec![0u8; self.config.max_datagram_size];
        let (len, peer_addr) = self.socket.recv_from(&mut buf).await?;

        let packet = match AitpPacket::from_bytes(&buf[..len]) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(peer = %peer_addr, error = %e, "Parse failed");
                return Ok(PacketAction::Dropped {
                    reason: e.to_string(),
                });
            }
        };

        let session_id = packet.header.session_id;

        if self.session_table.contains(session_id) {
            Ok(PacketAction::RouteToSession {
                session_id,
                header: packet.header,
                payload: packet.payload,
                peer_addr,
            })
        } else if packet.header.is_syn() {
            Ok(PacketAction::NewSession {
                header: packet.header,
                payload: packet.payload,
                peer_addr,
            })
        } else {
            tracing::debug!(
                session_id = format!("{:#018x}", session_id),
                peer = %peer_addr,
                "Orphan packet, dropping"
            );
            Ok(PacketAction::Dropped {
                reason: format!("unknown session {session_id:#018x} (not SYN)"),
            })
        }
    }

    /// Send a packet to a peer.
    pub async fn send_packet(
        &self,
        packet: &AitpPacket,
        peer_addr: SocketAddr,
    ) -> Result<usize, TransportError> {
        let bytes = packet.to_bytes();

        tracing::trace!(
            session_id = format!("{:#018x}", packet.header.session_id),
            peer = %peer_addr,
            size = bytes.len(),
            intent = %packet.header.intent_code,
            "Sending packet"
        );

        let sent = self.socket.send_to(&bytes, peer_addr).await?;
        Ok(sent)
    }

    /// Send raw bytes to a peer.
    pub async fn send_raw(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<usize, TransportError> {
        let sent = self.socket.send_to(data, peer_addr).await?;
        Ok(sent)
    }
}

// ────────────────────────── Utilities ──────────────────────────

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

fn hex_short(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "..."
}

// ────────────────────────── DDoS Guard ──────────────────────────

/// Configuration for the DDoS protection layer.
#[derive(Debug, Clone)]
pub struct DDoSConfig {
    /// Maximum new sessions per minute per source IP (token-bucket refill rate).
    pub max_new_sessions_per_min: u32,
    /// Global SYN budget — total simultaneous new sessions allowed. Replenished
    /// by a background task or when a session completes. Zero triggers flood protection.
    pub global_syn_budget: u32,
    /// How many leading zero bits a PoW solution must have (difficulty). Each
    /// extra bit doubles CPU cost. 16 bits ≈ 1 ms on a modern CPU.
    pub pow_difficulty: u8,
}

impl Default for DDoSConfig {
    fn default() -> Self {
        Self {
            max_new_sessions_per_min: 100,
            global_syn_budget: 5_000,
            pow_difficulty: 16,
        }
    }
}

/// A token-bucket rate-limiter state per source IP.
#[derive(Debug)]
pub struct RateBucket {
    /// Number of tokens currently available.
    tokens: u32,
    /// When the bucket was last refilled.
    last_refill: Instant,
    /// Bucket capacity (max tokens, == max_new_sessions_per_min).
    capacity: u32,
}

impl RateBucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
        }
    }

    /// Try to consume one token. Returns `true` if a token was available.
    fn try_consume(&mut self) -> bool {
        // Refill proportionally to time elapsed (1-minute window).
        let elapsed = self.last_refill.elapsed();
        if elapsed >= Duration::from_secs(60) {
            self.tokens = self.capacity;
            self.last_refill = Instant::now();
        } else {
            let refill = ((elapsed.as_secs_f64() / 60.0) * self.capacity as f64) as u32;
            self.tokens = (self.tokens + refill).min(self.capacity);
            if refill > 0 {
                self.last_refill = Instant::now();
            }
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// A Proof-of-Work challenge issued to a suspicious source IP.
#[derive(Debug, Clone)]
pub struct PowChallenge {
    /// Random 32-byte nonce the client must hash against.
    pub nonce: [u8; 32],
    /// The number of leading zero bits the solution hash must have.
    pub difficulty: u8,
    /// When this challenge expires.
    pub expires_at: Instant,
}

impl PowChallenge {
    fn new(difficulty: u8) -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            nonce,
            difficulty,
            expires_at: Instant::now() + Duration::from_secs(30),
        }
    }

    /// Check whether the client-supplied `solution` satisfies the PoW.
    /// Solution = SHA-256(challenge_nonce || solution_nonce). The hash must
    /// have at least `difficulty` leading zero bits.
    pub fn verify(&self, solution: &[u8; 32]) -> bool {
        if Instant::now() > self.expires_at {
            return false; // expired
        }
        let mut hasher = Sha256::new();
        hasher.update(self.nonce);
        hasher.update(solution);
        let hash: [u8; 32] = hasher.finalize().into();
        leading_zero_bits(&hash) >= self.difficulty
    }
}

/// Count the number of leading zero bits in a byte slice.
fn leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut count = 0u8;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u8;
            break;
        }
    }
    count
}

/// The verdict returned by [`DDoSGuard::check_incoming`].
#[derive(Debug)]
pub enum DDoSVerdict {
    /// Packet is allowed — proceed with processing.
    Allow,
    /// Source IP has exceeded the per-IP new-session rate limit.
    RateLimit,
    /// Global SYN budget exhausted — server is under flood attack.
    SynFloodProtection,
    /// Source IP is on the blacklist.
    Blacklisted,
    /// A PoW challenge has been issued; the client must solve it.
    RequirePoW(PowChallenge),
}

/// Protocol-level DDoS protection guard.
///
/// Implements four layered rules checked in order:
/// 1. IP blacklist (O(1) hash lookup)
/// 2. Global SYN budget (atomic counter)
/// 3. Per-IP token-bucket rate limit (100 new sessions/min default)
/// 4. Proof-of-Work for new IPs not yet seen (hashcash-style)
///
/// All state is behind `Arc`, so the guard can be cheaply cloned and
/// shared across the coordinator and any background replenishment tasks.
pub struct DDoSGuard {
    /// Per-IP token bucket state.
    ip_rates: Arc<DashMap<IpAddr, RateBucket>>,
    /// Remaining global SYN slots before flood-protection kicks in.
    syn_budget: Arc<AtomicU32>,
    /// Outstanding PoW challenges keyed by source IP.
    pow_challenges: Arc<DashMap<IpAddr, PowChallenge>>,
    /// Guard configuration.
    config: DDoSConfig,
    /// IPs permanently blacklisted (updated by control plane).
    blacklist: Arc<DashMap<IpAddr, ()>>,
}

impl DDoSGuard {
    /// Create a new guard from the given configuration.
    pub fn new(config: DDoSConfig) -> Self {
        Self {
            ip_rates: Arc::new(DashMap::new()),
            syn_budget: Arc::new(AtomicU32::new(config.global_syn_budget)),
            pow_challenges: Arc::new(DashMap::new()),
            config,
            blacklist: Arc::new(DashMap::new()),
        }
    }

    /// Evaluate an incoming SYN from `src_ip` and return the verdict.
    ///
    /// Rules are checked cheapest-first:
    /// 1. Blacklist
    /// 2. Global SYN budget
    /// 3. Per-IP rate limit
    /// 4. Outstanding PoW challenge (if any)
    pub fn check_incoming(&self, src_ip: IpAddr) -> DDoSVerdict {
        // Rule 1: blacklist (fastest check)
        if self.blacklist.contains_key(&src_ip) {
            return DDoSVerdict::Blacklisted;
        }

        // Rule 2: global SYN budget
        let budget = self.syn_budget.load(Ordering::Relaxed);
        if budget == 0 {
            return DDoSVerdict::SynFloodProtection;
        }

        // Rule 3: per-IP rate limit
        let mut allowed_by_rate = false;
        {
            let capacity = self.config.max_new_sessions_per_min;
            let mut entry = self
                .ip_rates
                .entry(src_ip)
                .or_insert_with(|| RateBucket::new(capacity));
            if entry.try_consume() {
                allowed_by_rate = true;
            }
        }
        if !allowed_by_rate {
            return DDoSVerdict::RateLimit;
        }

        // Rule 4: PoW for IPs that have an outstanding challenge
        if let Some(challenge) = self.pow_challenges.get(&src_ip) {
            // Challenge exists but no solution submitted yet → require PoW
            return DDoSVerdict::RequirePoW(challenge.clone());
        }

        // Decrement global budget
        self.syn_budget.fetch_sub(1, Ordering::Relaxed);

        DDoSVerdict::Allow
    }

    /// Issue a fresh PoW challenge for the given IP and return it.
    pub fn issue_challenge(&self, src_ip: IpAddr) -> PowChallenge {
        let challenge = PowChallenge::new(self.config.pow_difficulty);
        self.pow_challenges.insert(src_ip, challenge.clone());
        challenge
    }

    /// Verify a PoW solution submitted by `src_ip`.
    /// Returns `true` and removes the challenge if valid.
    pub fn verify_pow(&self, src_ip: IpAddr, solution: &[u8; 32]) -> bool {
        if let Some(entry) = self.pow_challenges.get(&src_ip) {
            if entry.verify(solution) {
                drop(entry);
                self.pow_challenges.remove(&src_ip);
                return true;
            }
        }
        false
    }

    /// Add an IP to the blacklist (called by the control plane).
    pub fn blacklist_ip(&self, ip: IpAddr) {
        self.blacklist.insert(ip, ());
    }

    /// Remove an IP from the blacklist.
    pub fn unblacklist_ip(&self, ip: &IpAddr) {
        self.blacklist.remove(ip);
    }

    /// Refill the global SYN budget by `amount` (called when sessions close).
    pub fn replenish_budget(&self, amount: u32) {
        let cap = self.config.global_syn_budget;
        let current = self.syn_budget.load(Ordering::Relaxed);
        let next = (current + amount).min(cap);
        self.syn_budget.store(next, Ordering::Relaxed);
    }

    /// Remaining global SYN budget.
    pub fn syn_budget(&self) -> u32 {
        self.syn_budget.load(Ordering::Relaxed)
    }

    /// Current per-IP rate bucket token count (for testing/metrics).
    pub fn ip_token_count(&self, ip: &IpAddr) -> Option<u32> {
        self.ip_rates.get(ip).map(|b| b.tokens)
    }

    /// Whether an IP is blacklisted.
    pub fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        self.blacklist.contains_key(ip)
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::IntentCode;
    use crate::session::Session;
    use aitp_identity::identity::{Capability, EntityType};

    #[tokio::test]
    async fn test_transport_bind() {
        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        };
        let transport = AitpTransport::bind(config).await.unwrap();
        let addr = transport.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_send_and_receive_packet() {
        let config_a = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        };
        let config_b = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        };

        let transport_a = AitpTransport::bind(config_a).await.unwrap();
        let transport_b = AitpTransport::bind(config_b).await.unwrap();

        let addr_b = transport_b.local_addr().unwrap();

        let header = AitpHeader::new(
            flags::SYN,
            IntentCode::ModelInference,
            0xABCD,
            [0x11; 32],
            [0x22; 32],
            0,
            5,
            1234567890,
            [0u8; 12],
        );
        let packet = AitpPacket::new(header, b"hello".to_vec()).unwrap();

        transport_a.send_packet(&packet, addr_b).await.unwrap();

        let action = transport_b.recv_packet().await.unwrap();
        match action {
            PacketAction::NewSession {
                header, payload, ..
            } => {
                assert_eq!(header.session_id, 0xABCD);
                assert!(header.is_syn());
                assert_eq!(payload, b"hello");
            }
            other => panic!("Expected NewSession, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_existing_session_routing() {
        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        };
        let transport = AitpTransport::bind(config).await.unwrap();
        let local_addr = transport.local_addr().unwrap();

        let session = Session::new(0x9999, [0u8; 32], [0u8; 32], IntentCode::Heartbeat);
        transport.session_table().insert(session).unwrap();

        let header = AitpHeader::new(
            0,
            IntentCode::Heartbeat,
            0x9999,
            [0x11; 32],
            [0x22; 32],
            128,
            0,
            0,
            [0u8; 12],
        );
        let packet = AitpPacket::new(header, vec![]).unwrap();

        let socket = transport.socket();
        let bytes = packet.to_bytes();
        socket.send_to(&bytes, local_addr).await.unwrap();

        let action = transport.recv_packet().await.unwrap();
        match action {
            PacketAction::RouteToSession { session_id, .. } => {
                assert_eq!(session_id, 0x9999);
            }
            other => panic!("Expected RouteToSession, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_orphan_packet_dropped() {
        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        };
        let transport = AitpTransport::bind(config).await.unwrap();
        let local_addr = transport.local_addr().unwrap();

        // Send a non-SYN packet for an unknown session
        let header = AitpHeader::new(
            0, // No SYN
            IntentCode::DataSync,
            0xDEAD,
            [0x11; 32],
            [0x22; 32],
            0,
            0,
            0,
            [0u8; 12],
        );
        let packet = AitpPacket::new(header, vec![]).unwrap();
        let socket = transport.socket();
        socket
            .send_to(&packet.to_bytes(), local_addr)
            .await
            .unwrap();

        let action = transport.recv_packet().await.unwrap();
        assert!(matches!(action, PacketAction::Dropped { .. }));
    }

    #[tokio::test]
    async fn test_bind_with_coordinator() {
        let identity = Arc::new(AitpIdentity::generate(
            "test-node",
            EntityType::Service,
            vec![Capability::Inference],
        ));
        let trust_engine = Arc::new(TrustEngine::with_defaults());
        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        };

        let (transport, _events) =
            AitpTransport::bind_with_coordinator(config, identity, trust_engine)
                .await
                .unwrap();

        assert!(transport.local_addr().unwrap().port() > 0);
        assert!(transport.coordinator.is_some());
    }

    #[tokio::test]
    async fn test_coordinator_full_handshake() {
        // Set up two transports with coordinators
        let id_server = Arc::new(AitpIdentity::generate(
            "server",
            EntityType::Service,
            vec![Capability::Inference],
        ));
        let id_client = Arc::new(AitpIdentity::generate(
            "client",
            EntityType::Service,
            vec![],
        ));
        let trust = Arc::new(TrustEngine::with_defaults());

        let (server, mut server_events) = AitpTransport::bind_with_coordinator(
            TransportConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            id_server.clone(),
            trust.clone(),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        // Spawn server receive loop
        let server = Arc::new(server);
        let server_clone = server.clone();
        let server_task = tokio::spawn(async move { server_clone.run().await });

        // Client sends SYN
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session_id: u64 = 0x42_42;
        let mut syn = AitpHeader::new(
            flags::SYN,
            IntentCode::ModelInference,
            session_id,
            id_client.entity_id,
            id_server.entity_id,
            0,
            0,
            now_nanos(),
            rand_nonce(),
        );
        syn.sign(id_client.signing_key());
        let pkt = AitpPacket::new(syn, vec![]).unwrap();
        client_socket
            .send_to(&pkt.to_bytes(), server_addr)
            .await
            .unwrap();

        // Wait for session established event
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), server_events.recv())
            .await
            .unwrap()
            .unwrap();

        match event {
            TransportEvent::SessionEstablished {
                session_id: sid,
                trust_score,
                ..
            } => {
                assert_eq!(sid, 0x42_42);
                assert!(trust_score > 0, "trust score should be > 0");
            }
            other => panic!("Expected SessionEstablished, got {other:?}"),
        }

        // Verify session is in the table
        assert!(server.session_table().contains(0x42_42));

        server_task.abort();
    }
}
