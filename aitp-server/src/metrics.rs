//! Kelan Security — Prometheus Metrics
//!
//! All metrics are registered globally once here via lazy_static.
//! Updated at the point of each event throughout the codebase.
//! Exposed at GET /metrics in Prometheus text exposition format.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram_vec,
    CounterVec, Encoder, Gauge, GaugeVec, HistogramVec, TextEncoder,
};

lazy_static! {
    // ─────────────────────────────────────────────────────────────────
    // Trust Engine
    // ─────────────────────────────────────────────────────────────────

    /// Total sessions evaluated, labelled by verdict + intent.
    pub static ref SESSIONS_TOTAL: CounterVec = register_counter_vec!(
        "kelan_sessions_total",
        "Total AITP sessions evaluated by the trust engine",
        &["verdict", "intent"]
    ).expect("metric registration failed");

    /// Full 5-phase AITP handshake / trust evaluation latency (ms).
    /// Buckets cover sub-ms rules path through to 50 ms Gemini-heavy evals.
    pub static ref HANDSHAKE_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_handshake_duration_ms",
        "Trust evaluation latency in milliseconds",
        &["source"],    // "rules" | "gemini" | "hybrid" | "rules_fallback"
        vec![0.5, 1.0, 2.0, 3.0, 5.0, 7.5, 10.0, 20.0, 50.0, 100.0]
    ).expect("metric registration failed");

    /// Gemini API round-trip latency (ms).
    pub static ref GEMINI_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_gemini_latency_ms",
        "Gemini API call latency in milliseconds",
        &["model", "outcome"],  // outcome: success | timeout | error | rate_limit
        vec![100.0, 250.0, 500.0, 1000.0, 2000.0, 3000.0, 4000.0, 5000.0, 8000.0, 15000.0]
    ).expect("metric registration failed");

    /// Trust score observed per session.
    pub static ref TRUST_SCORE: HistogramVec = register_histogram_vec!(
        "kelan_trust_score",
        "Trust score (0-255) assigned per session",
        &["verdict"],
        vec![0.0, 32.0, 64.0, 96.0, 128.0, 160.0, 192.0, 224.0, 255.0]
    ).expect("metric registration failed");

    /// Trust evaluation cache hit/miss.
    pub static ref TRUST_CACHE: CounterVec = register_counter_vec!(
        "kelan_trust_cache_total",
        "Trust evaluation cache lookups",
        &["result"]  // "hit" | "miss"
    ).expect("metric registration failed");

    /// Gemini API error counter.
    pub static ref GEMINI_ERRORS: CounterVec = register_counter_vec!(
        "kelan_gemini_errors_total",
        "Gemini API errors broken down by type",
        &["error_type"]  // "timeout" | "rate_limit" | "auth" | "network" | "parse"
    ).expect("metric registration failed");

    // ─────────────────────────────────────────────────────────────────
    // Session state (gauges — go up and down)
    // ─────────────────────────────────────────────────────────────────

    /// Currently active sessions.
    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "kelan_active_sessions",
        "Number of currently active AITP sessions"
    ).expect("metric registration failed");

    /// Smoothed session evaluation rate (sessions/sec).
    pub static ref SESSION_RATE: Gauge = register_gauge!(
        "kelan_session_rate_per_second",
        "Session evaluation rate (sessions/sec, rolling 5s window)"
    ).expect("metric registration failed");

    // ─────────────────────────────────────────────────────────────────
    // eBPF / XDP enforcement
    // ─────────────────────────────────────────────────────────────────

    /// Packets processed by the XDP program.
    pub static ref EBPF_PACKETS: CounterVec = register_counter_vec!(
        "kelan_ebpf_packets_total",
        "Packets processed by eBPF XDP enforcement",
        &["action"]   // "pass" | "drop" | "bypass" | "aborted"
    ).expect("metric registration failed");

    /// eBPF enforcement mode per interface.
    pub static ref EBPF_MODE: GaugeVec = register_gauge_vec!(
        "kelan_ebpf_mode",
        "eBPF enforcement mode (1 = XDP active, 0 = software fallback)",
        &["interface"]
    ).expect("metric registration failed");

    /// Active XDP session permits in the BPF map.
    pub static ref EBPF_PERMITS: Gauge = register_gauge!(
        "kelan_ebpf_active_permits",
        "Number of session permits currently held in the eBPF map"
    ).expect("metric registration failed");

    // ─────────────────────────────────────────────────────────────────
    // Sentinel
    // ─────────────────────────────────────────────────────────────────

    /// Anomalies detected, by type and severity.
    pub static ref ANOMALIES_DETECTED: CounterVec = register_counter_vec!(
        "kelan_anomalies_total",
        "Anomalies detected by the Kelan Sentinel",
        &["anomaly_type", "severity"]
    ).expect("metric registration failed");

    /// Sentinel event channel depth (pending events).
    pub static ref SENTINEL_CHANNEL_DEPTH: Gauge = register_gauge!(
        "kelan_sentinel_channel_depth",
        "Events pending in the Sentinel mpsc channel"
    ).expect("metric registration failed");

    /// How long it takes to detect an anomaly from event arrival (ms).
    pub static ref ANOMALY_DETECTION_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_anomaly_detection_ms",
        "Latency from session event to anomaly detection (ms)",
        &["signal_type"],  // "critical" | "elevated" | "routine"
        vec![0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0, 500.0]
    ).expect("metric registration failed");

    /// Entities currently quarantined.
    pub static ref QUARANTINED_ENTITIES: Gauge = register_gauge!(
        "kelan_quarantined_entities",
        "Number of entities currently quarantined"
    ).expect("metric registration failed");

    // ─────────────────────────────────────────────────────────────────
    // Threat Response Agent
    // ─────────────────────────────────────────────────────────────────

    /// Security incidents detected by the Threat Response agent.
    pub static ref THREAT_INCIDENTS: CounterVec = register_counter_vec!(
        "kelan_threat_incidents_total",
        "Security incidents detected by the Threat Response agent",
        &["severity", "attack_type"]
    ).expect("metric registration failed");

    // ─────────────────────────────────────────────────────────────────
    // WebSocket hub
    // ─────────────────────────────────────────────────────────────────

    /// Number of connected WebSocket dashboard clients.
    pub static ref WS_SUBSCRIBERS: Gauge = register_gauge!(
        "kelan_ws_subscribers",
        "Number of connected WebSocket dashboard subscribers"
    ).expect("metric registration failed");

    /// WebSocket events broadcast.
    pub static ref WS_EVENTS: CounterVec = register_counter_vec!(
        "kelan_ws_events_total",
        "WebSocket events broadcast to dashboard clients",
        &["event_type"]
    ).expect("metric registration failed");

    // ─────────────────────────────────────────────────────────────────
    // Database
    // ─────────────────────────────────────────────────────────────────

    /// DB connection pool state.
    pub static ref DB_POOL_CONNECTIONS: GaugeVec = register_gauge_vec!(
        "kelan_db_pool_connections",
        "Database connection pool utilisation",
        &["state"]   // "active" | "idle"
    ).expect("metric registration failed");

    // ─────────────────────────────────────────────────────────────────
    // Business / Licensing
    // ─────────────────────────────────────────────────────────────────

    /// License node limit utilisation ratio (current / max).
    pub static ref LICENSE_UTILISATION: GaugeVec = register_gauge_vec!(
        "kelan_license_utilisation",
        "License node utilisation ratio (0.0-1.0)",
        &["org_id", "tier"]
    ).expect("metric registration failed");

    /// Registered entities per organisation.
    pub static ref REGISTERED_ENTITIES: GaugeVec = register_gauge_vec!(
        "kelan_registered_entities",
        "Number of entities registered per organisation",
        &["org_id", "tier"]
    ).expect("metric registration failed");

    /// Database query latency by operation type.
    pub static ref DB_QUERY_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_db_query_ms",
        "Database query latency in milliseconds",
        &["operation"],  // select | insert | update | delete
        vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0, 500.0]
    ).expect("metric registration failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP handler
// ─────────────────────────────────────────────────────────────────────────────

/// GET /metrics — Prometheus text exposition format.
/// This route requires no authentication so Prometheus can scrape it freely.
pub async fn metrics_handler() -> impl axum::response::IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::with_capacity(16 * 1024);
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!("Failed to encode Prometheus metrics: {}", e);
    }
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buffer,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience helpers (keep hot paths terse)
// ─────────────────────────────────────────────────────────────────────────────

/// Record a completed trust evaluation.
pub fn record_session(
    verdict: &str,
    intent: &str,
    latency_ms: f64,
    trust_score: u8,
    source: &str,
) {
    SESSIONS_TOTAL.with_label_values(&[verdict, intent]).inc();
    HANDSHAKE_LATENCY.with_label_values(&[source]).observe(latency_ms);
    TRUST_SCORE.with_label_values(&[verdict]).observe(trust_score as f64);
}

/// Record a Gemini API call result.
pub fn record_gemini_call(model: &str, outcome: &str, latency_ms: f64) {
    GEMINI_LATENCY.with_label_values(&[model, outcome]).observe(latency_ms);
    if outcome != "success" {
        GEMINI_ERRORS.with_label_values(&[outcome]).inc();
    }
}

/// Record a Sentinel anomaly detection event.
pub fn record_anomaly(
    anomaly_type: &str,
    severity: &str,
    detection_latency_ms: f64,
    signal_type: &str,
) {
    ANOMALIES_DETECTED
        .with_label_values(&[anomaly_type, severity])
        .inc();
    ANOMALY_DETECTION_LATENCY
        .with_label_values(&[signal_type])
        .observe(detection_latency_ms);
}
