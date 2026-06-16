//! Alert engine — subscribes to the AITP EventBus and converts events to security alerts.

use super::state::{AlertEntry, AlertType, ConnectedClient, LogEntry, LogLevel, ServerState};
use crate::events::{AitpEvent, AitpEventKind, DropReason};
use crate::header::IntentCode;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Subscribes to events from the AITP EventBus and populates `ServerState`.
///
/// Run this in a background task alongside the transport:
/// ```no_run
/// # use std::sync::Arc;
/// # use aitp_core::server::alert_engine::AlertEngine;
/// # use aitp_core::server::state::ServerState;
/// # use aitp_core::events::EventBus;
/// # #[tokio::main]
/// # async fn main() {
/// # let state = Arc::new(ServerState::new());
/// # let event_bus = EventBus::new();
/// let alert_engine = AlertEngine::new(state.clone(), event_bus.subscribe());
/// tokio::spawn(async move { alert_engine.run().await });
/// # }
/// ```
pub struct AlertEngine {
    state: Arc<ServerState>,
    rx: broadcast::Receiver<AitpEvent>,
}

impl AlertEngine {
    pub fn new(state: Arc<ServerState>, rx: broadcast::Receiver<AitpEvent>) -> Self {
        Self { state, rx }
    }

    /// Run the alert engine until the event channel closes or the task is cancelled.
    pub async fn run(mut self) {
        loop {
            match self.rx.recv().await {
                Ok(event) => self.handle(event),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let entry = LogEntry::new(
                        LogLevel::Warn,
                        format!("Alert engine lagged: skipped {n} events"),
                    );
                    self.state.push_log(entry);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }

    fn handle(&self, event: AitpEvent) {
        match event.kind {
            // ── Session initiated ────────────────────────────────────────────
            AitpEventKind::SessionInitiated {
                session_id,
                source,
                dest: _,
                intent,
            } => {
                // Anonymous identity check — all-zero entity_id.
                if source == [0u8; 32] {
                    let alert = AlertEntry::new(
                        AlertType::AnonymousConnection,
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        format!(
                            "session {session_id:#018x} — entity_id=MISSING. \
                             Action: AITP_REJECT + BLACKLIST 60s"
                        ),
                    );
                    self.state.push_alert(alert.clone());
                    self.state.push_log(
                        LogEntry::new(LogLevel::Alert, "Anonymous connection attempt")
                            .with_meta("session_id", format!("{session_id:#018x}"))
                            .with_meta("action", "REJECT"),
                    );
                    return;
                }

                self.state.push_log(
                    LogEntry::new(LogLevel::Info, "Session initiated")
                        .with_meta("session_id", format!("{session_id:#018x}"))
                        .with_meta("intent", IntentCode::from_u16(intent).as_str()),
                );
            }

            // ── Handshake complete ───────────────────────────────────────────
            AitpEventKind::HandshakeComplete {
                session_id,
                trust_score,
                eval_time_ns,
            } => {
                let level = if trust_score > 150 {
                    LogLevel::Ok
                } else if trust_score > 100 {
                    LogLevel::Warn
                } else {
                    LogLevel::Alert
                };
                let verdict = verdict_label(trust_score);
                self.state.push_log(
                    LogEntry::new(level, format!("Session ESTABLISHED — {verdict}"))
                        .with_meta("session_id", format!("{session_id:#018x}"))
                        .with_meta("trust", trust_score.to_string())
                        .with_meta(
                            "eval_ms",
                            format!("{:.2}", eval_time_ns as f64 / 1_000_000.0),
                        ),
                );
            }

            // ── Trust score updated ──────────────────────────────────────────
            AitpEventKind::TrustScoreUpdated {
                session_id,
                old_score,
                new_score,
            } => {
                let delta: i16 = new_score as i16 - old_score as i16;
                let sign = if delta >= 0 { "+" } else { "" };
                self.state.push_log(
                    LogEntry::new(LogLevel::Trust, format!("Trust re-eval → {new_score}"))
                        .with_meta("session_id", format!("{session_id:#018x}"))
                        .with_meta("delta", format!("{sign}{delta}"))
                        .with_meta("verdict", verdict_label(new_score)),
                );

                // Score collapsed by > 50 points in one eval → alert.
                if (old_score as i16 - new_score as i16) > 50 {
                    let alert = AlertEntry::new(
                        AlertType::ScoreCollapse,
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        format!(
                            "session {session_id:#018x} — score {old_score} → {new_score} \
                             (Δ={delta}). Possible behavioral pivot."
                        ),
                    );
                    self.state.push_alert(alert);
                }

                // Update connected client's trust score in the client map.
                if let Some(mut client) = self.state.clients.get_mut(&session_id) {
                    client.trust_score = new_score;
                }
            }

            // ── Packet dropped ───────────────────────────────────────────────
            AitpEventKind::PacketDropped { reason, source_ip } => {
                self.state
                    .stats
                    .blocked_packets
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let (level, msg, alert_opt) = match &reason {
                    DropReason::InvalidSignature => (
                        LogLevel::Warn,
                        format!("Dropped: invalid signature from {source_ip}"),
                        None,
                    ),
                    DropReason::RateLimited => (
                        LogLevel::Warn,
                        format!("Dropped: rate-limited {source_ip}"),
                        Some(AlertEntry::new(
                            AlertType::SynFlood,
                            source_ip,
                            format!("Rate limit exceeded by {source_ip}"),
                        )),
                    ),
                    DropReason::ParseError(e) => {
                        (LogLevel::Warn, format!("Dropped: parse error — {e}"), None)
                    }
                    DropReason::OrphanPacket { session_id } => (
                        LogLevel::Sys,
                        format!("Dropped: orphan packet for session {session_id:#018x}"),
                        None,
                    ),
                    DropReason::OversizedDatagram { size, max } => (
                        LogLevel::Warn,
                        format!("Dropped: oversized {size}B (max {max}B) from {source_ip}"),
                        None,
                    ),
                };

                self.state.push_log(LogEntry::new(level, msg));
                if let Some(alert) = alert_opt {
                    self.state.push_alert(alert);
                }
            }

            // ── Session revoked ──────────────────────────────────────────────
            AitpEventKind::SessionRevoked {
                session_id,
                reason,
                initiated_by: _,
            } => {
                self.state.remove_client(session_id);
                self.state.push_log(
                    LogEntry::new(LogLevel::Warn, format!("Session REVOKED — {reason}"))
                        .with_meta("session_id", format!("{session_id:#018x}")),
                );
            }

            // ── Session closed ───────────────────────────────────────────────
            AitpEventKind::SessionClosed { session_id } => {
                self.state.remove_client(session_id);
                self.state.push_log(
                    LogEntry::new(LogLevel::Ok, "Session closed gracefully")
                        .with_meta("session_id", format!("{session_id:#018x}")),
                );
            }

            // ── Payload events ───────────────────────────────────────────────
            AitpEventKind::PayloadReceived { session_id, bytes } => {
                if let Some(mut client) = self.state.clients.get_mut(&session_id) {
                    client.packets_received += 1;
                    client.bytes_received += bytes as u64;
                }
            }

            AitpEventKind::PayloadSent { .. } => {}
        }
    }

    /// Called externally when the transport adds a new client to track.
    pub fn register_client(&self, client: ConnectedClient) {
        self.state.push_log(
            LogEntry::new(LogLevel::Ok, "New client connected")
                .with_meta("session_id", format!("{:#018x}", client.session_id))
                .with_meta("trust", client.trust_score.to_string())
                .with_meta("intent", client.intent.as_str()),
        );
        self.state.add_client(client);
    }

    /// Called when an IP triggers Sybil heuristics.
    pub fn check_sybil(&self, source_ip: IpAddr) {
        self.state.record_new_id_from_ip(source_ip);
        let count = self.state.count_new_ids_from_ip(source_ip);
        if count > 10 {
            let alert = AlertEntry::new(
                AlertType::SybilSuspect,
                source_ip,
                format!("{count} distinct new identities from {source_ip} — Sybil pattern"),
            );
            self.state.push_alert(alert);
        }
    }

    /// Called when the intent fingerprint detects a divergence.
    pub fn report_intent_mismatch(
        &self,
        session_id: u64,
        declared: IntentCode,
        description: &str,
        source_addr: SocketAddr,
    ) {
        self.state.push_log(
            LogEntry::new(
                LogLevel::Intent,
                format!(
                    "Intent mismatch for session {session_id:#018x}: declared={declared} — {description}"
                ),
            )
            .with_meta("action", "MONITORING escalated"),
        );
        let alert = AlertEntry::new(
            AlertType::IntentMismatch,
            source_addr.ip(),
            format!(
                "session {session_id:#018x} declared {declared} but behavior diverges: {description}"
            ),
        );
        self.state.push_alert(alert);
    }
}

fn verdict_label(score: u8) -> &'static str {
    match score {
        185..=255 => "ALLOW",
        128..=184 => "MONITOR",
        64..=127 => "RESTRICT",
        _ => "DENY",
    }
}
