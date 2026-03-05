//! Behavioral telemetry intake for trust evaluation.
//!
//! Collects session-level behavioral signals used by the trust engine
//! to detect anomalies and adjust trust scores over time.

use serde::{Deserialize, Serialize};

/// Behavioral flags observed during a session.
///
/// These flags are collected by the telemetry system and fed into
/// the trust engine for continuous authorization decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorFlag {
    /// Normal behavior — no anomalies detected.
    Normal,
    /// Unusually high request rate.
    HighFrequency,
    /// Payload size exceeds expected bounds.
    OversizedPayload,
    /// Intent has shifted during an active session.
    IntentDrift,
    /// Requests arriving from a new IP address.
    GeoShift,
    /// Timing patterns suggest automated probing.
    ProbePattern,
    /// Repeated authentication failures.
    AuthFailures,
    /// First-time connection from this identity.
    NewIdentity,
}

/// Telemetry snapshot for a single session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTelemetry {
    /// Session identifier.
    pub session_id: u64,
    /// Behavioral flags observed.
    pub flags: Vec<BehaviorFlag>,
    /// Total packets sent in this session.
    pub packets_sent: u64,
    /// Total packets received in this session.
    pub packets_received: u64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Session duration in milliseconds.
    pub duration_ms: u64,
}

/// Collects and manages telemetry data for active sessions.
#[derive(Debug, Default)]
pub struct TelemetryCollector {
    // In MVP, telemetry is passed directly via TrustContext.
    // This struct is a placeholder for the v0.3 behavioral telemetry pipeline.
}

impl TelemetryCollector {
    /// Create a new telemetry collector.
    pub fn new() -> Self {
        Self {}
    }
}
