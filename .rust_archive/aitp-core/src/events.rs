//! Structured event bus for AITP session lifecycle events.
//!
//! Every session lifecycle event is emitted to an internal
//! [`tokio::sync::broadcast`] channel so that subsystems (observability,
//! AI engine, control plane) can subscribe independently.
//!
//! # Architecture
//!
//! ```text
//! Transport ──┐
//! Handshake ──┤──→ EventBus (broadcast, cap=1024) ──→ Subscriber A (observability)
//! Trust      ──┤                                   ──→ Subscriber B (AI engine)
//! Control   ──┘                                    ──→ Subscriber C (control plane)
//! ```

use crate::header::IntentCode;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// Capacity of the broadcast channel.
const EVENT_BUS_CAPACITY: usize = 1024;

/// A 32-byte entity identifier (SHA-256 of Ed25519 public key).
pub type EntityId = [u8; 32];

// ────────────────────────── Drop / Revoke Reasons ──────────────────────────

/// Reason a packet was dropped.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum DropReason {
    /// Packet could not be parsed (invalid header or framing).
    ParseError(String),
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Packet for an unknown session that is not a SYN.
    OrphanPacket { session_id: u64 },
    /// Datagram exceeds maximum configured size.
    OversizedDatagram { size: usize, max: usize },
    /// Rate-limited: too many packets from this source.
    RateLimited,
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(e) => write!(f, "parse error: {e}"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::OrphanPacket { session_id } => {
                write!(f, "orphan packet: session {session_id:#018x}")
            }
            Self::OversizedDatagram { size, max } => {
                write!(f, "oversized: {size} bytes (max {max})")
            }
            Self::RateLimited => write!(f, "rate limited"),
        }
    }
}

/// Reason a session was revoked.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum RevokeReason {
    /// Trust engine denied the session.
    TrustDenied { trust_score: u8 },
    /// Peer sent an explicit REVOKE packet.
    PeerRevoked,
    /// Session expired due to inactivity.
    Timeout,
    /// Administrative revocation from control plane.
    Administrative(String),
}

impl std::fmt::Display for RevokeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrustDenied { trust_score } => {
                write!(f, "trust denied (score={trust_score})")
            }
            Self::PeerRevoked => write!(f, "peer revoked"),
            Self::Timeout => write!(f, "timeout"),
            Self::Administrative(msg) => write!(f, "admin: {msg}"),
        }
    }
}

// ────────────────────────── Event Enum ──────────────────────────

/// A structured lifecycle event emitted by the AITP transport.
///
/// All events carry a monotonic sequence number and nanosecond timestamp
/// for causal ordering and observability correlation.
#[derive(Debug, Clone, Serialize)]
pub struct AitpEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Nanosecond timestamp (UNIX epoch).
    pub timestamp_ns: u64,
    /// The event payload.
    pub kind: AitpEventKind,
}

/// The kind of lifecycle event.
#[derive(Debug, Clone, Serialize)]
pub enum AitpEventKind {
    /// A new session handshake has been initiated (SYN received).
    SessionInitiated {
        session_id: u64,
        source: EntityId,
        dest: EntityId,
        intent: u16,
    },

    /// Handshake completed successfully — session is now active.
    HandshakeComplete {
        session_id: u64,
        trust_score: u8,
        eval_time_ns: u64,
    },

    /// Data payload received on an active session.
    PayloadReceived { session_id: u64, bytes: usize },

    /// Data payload sent on an active session.
    PayloadSent { session_id: u64, bytes: usize },

    /// A session was revoked.
    SessionRevoked {
        session_id: u64,
        reason: RevokeReason,
        initiated_by: EntityId,
    },

    /// A session was gracefully closed (FIN).
    SessionClosed { session_id: u64 },

    /// Trust score was updated for a session.
    TrustScoreUpdated {
        session_id: u64,
        old_score: u8,
        new_score: u8,
    },

    /// A packet was dropped.
    PacketDropped {
        reason: DropReason,
        source_ip: IpAddr,
    },
}

// ────────────────────────── Event Bus ──────────────────────────

/// Errors from the event bus.
#[derive(Debug, thiserror::Error)]
pub enum EventBusError {
    /// No active subscribers — event was not delivered.
    #[error("no active subscribers for event (seq={seq})")]
    NoSubscribers { seq: u64 },
}

/// A broadcast-based event bus for AITP lifecycle events.
///
/// Subsystems subscribe by calling [`subscribe()`](EventBus::subscribe)
/// to get a [`broadcast::Receiver<AitpEvent>`]. Events emitted via
/// [`emit()`](EventBus::emit) are delivered to all active subscribers.
///
/// If a subscriber falls behind by more than [`EVENT_BUS_CAPACITY`]
/// events, it will receive a [`broadcast::error::RecvError::Lagged`]
/// error and skip the missed events.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<AitpEvent>,
    seq: std::sync::Arc<AtomicU64>,
}

impl EventBus {
    /// Create a new event bus with the default capacity (1024).
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        Self {
            tx,
            seq: std::sync::Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a new event bus with a custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            seq: std::sync::Arc::new(AtomicU64::new(0)),
        }
    }

    /// Subscribe to the event bus.
    ///
    /// Returns a [`broadcast::Receiver`] that will receive all events
    /// emitted after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<AitpEvent> {
        self.tx.subscribe()
    }

    /// Emit an event to all subscribers.
    ///
    /// The event is stamped with a monotonic sequence number and
    /// the current nanosecond timestamp.
    ///
    /// Returns `Ok(num_receivers)` on success, or
    /// [`EventBusError::NoSubscribers`] if nobody is listening.
    #[tracing::instrument(skip(self, kind), fields(event_kind = std::any::type_name::<AitpEventKind>()))]
    pub fn emit(&self, kind: AitpEventKind) -> Result<usize, EventBusError> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let event = AitpEvent {
            seq,
            timestamp_ns,
            kind,
        };

        self.tx
            .send(event)
            .map_err(|_| EventBusError::NoSubscribers { seq })
    }

    /// Emit an event, silently dropping it if there are no subscribers.
    ///
    /// This is the preferred method when the caller doesn't care whether
    /// anyone is listening (e.g., optional observability).
    pub fn emit_lossy(&self, kind: AitpEventKind) {
        let _ = self.emit(kind);
    }

    /// Get the number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Get the next sequence number (for testing).
    pub fn next_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    // ── Convenience emitters for common events ──

    /// Emit a SessionInitiated event.
    pub fn session_initiated(
        &self,
        session_id: u64,
        source: EntityId,
        dest: EntityId,
        intent: IntentCode,
    ) {
        self.emit_lossy(AitpEventKind::SessionInitiated {
            session_id,
            source,
            dest,
            intent: intent as u16,
        });
    }

    /// Emit a HandshakeComplete event.
    pub fn handshake_complete(&self, session_id: u64, trust_score: u8, eval_time_ns: u64) {
        self.emit_lossy(AitpEventKind::HandshakeComplete {
            session_id,
            trust_score,
            eval_time_ns,
        });
    }

    /// Emit a PayloadReceived event.
    pub fn payload_received(&self, session_id: u64, bytes: usize) {
        self.emit_lossy(AitpEventKind::PayloadReceived { session_id, bytes });
    }

    /// Emit a PayloadSent event.
    pub fn payload_sent(&self, session_id: u64, bytes: usize) {
        self.emit_lossy(AitpEventKind::PayloadSent { session_id, bytes });
    }

    /// Emit a SessionRevoked event.
    pub fn session_revoked(&self, session_id: u64, reason: RevokeReason, initiated_by: EntityId) {
        self.emit_lossy(AitpEventKind::SessionRevoked {
            session_id,
            reason,
            initiated_by,
        });
    }

    /// Emit a SessionClosed event.
    pub fn session_closed(&self, session_id: u64) {
        self.emit_lossy(AitpEventKind::SessionClosed { session_id });
    }

    /// Emit a TrustScoreUpdated event.
    pub fn trust_score_updated(&self, session_id: u64, old_score: u8, new_score: u8) {
        self.emit_lossy(AitpEventKind::TrustScoreUpdated {
            session_id,
            old_score,
            new_score,
        });
    }

    /// Emit a PacketDropped event.
    pub fn packet_dropped(&self, reason: DropReason, source_ip: IpAddr) {
        self.emit_lossy(AitpEventKind::PacketDropped { reason, source_ip });
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("subscribers", &self.subscriber_count())
            .field("next_seq", &self.next_seq())
            .finish()
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_bus_emit_and_receive() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        bus.session_initiated(0x1234, [0xAA; 32], [0xBB; 32], IntentCode::ModelInference);

        let event = rx.try_recv().expect("should receive event");
        assert_eq!(event.seq, 0);
        match event.kind {
            AitpEventKind::SessionInitiated {
                session_id, intent, ..
            } => {
                assert_eq!(session_id, 0x1234);
                assert_eq!(intent, IntentCode::ModelInference as u16);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn test_monotonic_sequence() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        bus.session_initiated(1, [0; 32], [0; 32], IntentCode::DataSync);
        bus.handshake_complete(1, 128, 5000);
        bus.payload_received(1, 1024);

        let e1 = rx.try_recv().expect("event 1");
        let e2 = rx.try_recv().expect("event 2");
        let e3 = rx.try_recv().expect("event 3");

        assert_eq!(e1.seq, 0);
        assert_eq!(e2.seq, 1);
        assert_eq!(e3.seq, 2);
        assert!(e1.timestamp_ns <= e2.timestamp_ns);
        assert!(e2.timestamp_ns <= e3.timestamp_ns);
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.session_closed(42);

        let e1 = rx1.try_recv().expect("subscriber 1");
        let e2 = rx2.try_recv().expect("subscriber 2");

        assert_eq!(e1.seq, e2.seq);
        assert!(matches!(
            e1.kind,
            AitpEventKind::SessionClosed { session_id: 42 }
        ));
        assert!(matches!(
            e2.kind,
            AitpEventKind::SessionClosed { session_id: 42 }
        ));
    }

    #[test]
    fn test_no_subscribers_lossy() {
        let bus = EventBus::new();
        // No subscribers — should not panic
        bus.emit_lossy(AitpEventKind::SessionClosed { session_id: 0 });
        assert_eq!(bus.next_seq(), 1);
    }

    #[test]
    fn test_no_subscribers_error() {
        let bus = EventBus::new();
        let result = bus.emit(AitpEventKind::SessionClosed { session_id: 0 });
        assert!(result.is_err());
        match result {
            Err(EventBusError::NoSubscribers { seq }) => assert_eq!(seq, 0),
            _ => panic!("expected NoSubscribers error"),
        }
    }

    #[test]
    fn test_subscriber_count() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(), 0);

        let _rx1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        drop(_rx1);
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[test]
    fn test_revoke_reason_display() {
        let r = RevokeReason::TrustDenied { trust_score: 42 };
        assert_eq!(r.to_string(), "trust denied (score=42)");

        let r = RevokeReason::PeerRevoked;
        assert_eq!(r.to_string(), "peer revoked");
    }

    #[test]
    fn test_drop_reason_display() {
        let d = DropReason::OrphanPacket { session_id: 0xABCD };
        assert!(d.to_string().contains("orphan"));

        let d = DropReason::InvalidSignature;
        assert_eq!(d.to_string(), "invalid signature");
    }

    #[test]
    fn test_event_serialization() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        bus.packet_dropped(
            DropReason::InvalidSignature,
            "192.168.1.1".parse().expect("valid IP"),
        );

        let event = rx.try_recv().expect("should receive");
        let json = serde_json::to_string(&event).expect("serializable");
        assert!(json.contains("InvalidSignature"));
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn test_trust_score_updated() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        bus.trust_score_updated(0xFF, 50, 128);

        let event = rx.try_recv().expect("should receive");
        match event.kind {
            AitpEventKind::TrustScoreUpdated {
                session_id,
                old_score,
                new_score,
            } => {
                assert_eq!(session_id, 0xFF);
                assert_eq!(old_score, 50);
                assert_eq!(new_score, 128);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
