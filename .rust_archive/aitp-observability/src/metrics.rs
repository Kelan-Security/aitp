//! Observability metrics — Prometheus exporter for AITP protocol events.
//!
//! Exports standard AITP metrics:
//! - `aitp_sessions_active` (gauge)
//! - `aitp_sessions_total` (counter, by intent)
//! - `aitp_trust_eval_duration_ms` (histogram)
//! - `aitp_sessions_revoked_total` (counter)
//! - `aitp_packets_dropped_total` (counter, by reason)
//! - `aitp_handshake_duration_ms` (histogram)

use once_cell::sync::Lazy;
use prometheus::{
    register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    Histogram, IntCounter, IntCounterVec, IntGauge,
};

/// Active AITP sessions (gauge).
pub static SESSIONS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aitp_sessions_active",
        "Number of currently active AITP sessions"
    )
    .unwrap()
});

/// Total AITP sessions established (counter, labeled by intent).
pub static SESSIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aitp_sessions_total",
        "Total AITP sessions established",
        &["intent"]
    )
    .unwrap()
});

/// Trust evaluation duration in milliseconds (histogram).
pub static TRUST_EVAL_DURATION_MS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "aitp_trust_eval_duration_ms",
        "Trust evaluation duration in milliseconds",
        vec![0.1, 0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0]
    )
    .unwrap()
});

/// Total sessions revoked (counter).
pub static SESSIONS_REVOKED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("aitp_sessions_revoked_total", "Total AITP sessions revoked").unwrap()
});

/// Total packets dropped (counter, labeled by reason).
pub static PACKETS_DROPPED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aitp_packets_dropped_total",
        "Total AITP packets dropped",
        &["reason"]
    )
    .unwrap()
});

/// Handshake duration in milliseconds (histogram).
pub static HANDSHAKE_DURATION_MS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "aitp_handshake_duration_ms",
        "Handshake duration in milliseconds",
        vec![1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 2000.0]
    )
    .unwrap()
});
