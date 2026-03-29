//! Kelan Security — Prometheus Metrics
//!
//! All metrics are registered globally here.
//! Updated throughout the codebase at the point of each event.
//! Exposed at GET /metrics in Prometheus text format.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec,
    register_histogram_vec, CounterVec, Gauge, GaugeVec, HistogramVec,
    TextEncoder, Encoder,
};

lazy_static! {
    // ── Trust Engine ──────────────────────────────────────────────────────

    /// Total sessions evaluated, labelled by verdict
    pub static ref SESSIONS_TOTAL: CounterVec = register_counter_vec!(
        "kelan_sessions_total",
        "Total AITP sessions evaluated",
        &["verdict", "intent", "org_id"]
    ).unwrap();

    /// Session evaluation latency (the full 5-phase handshake)
    pub static ref HANDSHAKE_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_handshake_duration_ms",
        "5-phase AITP handshake latency in milliseconds",
        &["trust_mode"],
        vec![0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 7.5, 10.0, 20.0, 50.0]
    ).unwrap();

    /// Gemini API call latency
    pub static ref GEMINI_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_gemini_latency_ms",
        "Gemini 2.5 API call latency in milliseconds",
        &["model", "outcome"],  // outcome: success | timeout | error
        vec![100.0, 500.0, 1000.0, 2000.0, 3000.0, 4000.0, 5000.0, 8000.0, 15000.0]
    ).unwrap();

    /// Trust score distribution
    pub static ref TRUST_SCORE: HistogramVec = register_histogram_vec!(
        "kelan_trust_score",
        "Trust score assigned to sessions (0-255)",
        &["verdict"],
        vec![0.0, 32.0, 64.0, 96.0, 128.0, 160.0, 192.0, 224.0, 255.0]
    ).unwrap();

    /// Trust cache hit/miss counter
    pub static ref TRUST_CACHE: CounterVec = register_counter_vec!(
        "kelan_trust_cache_total",
        "Trust evaluation cache hits and misses",
        &["result"]  // hit | miss
    ).unwrap();

    /// Gemini API errors
    pub static ref GEMINI_ERRORS: CounterVec = register_counter_vec!(
        "kelan_gemini_errors_total",
        "Gemini API errors by type",
        &["error_type"]  // timeout | rate_limit | auth | network | parse
    ).unwrap();

    // ── Session State ─────────────────────────────────────────────────────

    /// Currently active sessions (gauge — goes up and down)
    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "kelan_active_sessions",
        "Number of currently active AITP sessions"
    ).unwrap();

    /// Session rate (sessions per second — rolling gauge)
    pub static ref SESSION_RATE: Gauge = register_gauge!(
        "kelan_session_rate_per_second",
        "Current session evaluation rate (sessions/sec)"
    ).unwrap();

    // ── eBPF Enforcement ──────────────────────────────────────────────────

    /// Packets processed by XDP program
    pub static ref EBPF_PACKETS: CounterVec = register_counter_vec!(
        "kelan_ebpf_packets_total",
        "Packets processed by eBPF XDP enforcement",
        &["action"]   // pass | drop | bypass | aborted
    ).unwrap();

    /// XDP enforcement mode
    pub static ref EBPF_MODE: GaugeVec = register_gauge_vec!(
        "kelan_ebpf_mode",
        "eBPF enforcement mode (1=active, 0=software fallback)",
        &["interface"]
    ).unwrap();

    /// Active XDP permits in the BPF map
    pub static ref EBPF_PERMITS: Gauge = register_gauge!(
        "kelan_ebpf_active_permits",
        "Number of session permits currently in the eBPF map"
    ).unwrap();

    // ── Sentinel ──────────────────────────────────────────────────────────

    /// Anomalies detected by type and severity
    pub static ref ANOMALIES_DETECTED: CounterVec = register_counter_vec!(
        "kelan_anomalies_total",
        "Anomalies detected by the Sentinel",
        &["anomaly_type", "severity", "org_id"]
    ).unwrap();

    /// Sentinel event channel utilisation
    pub static ref SENTINEL_CHANNEL_DEPTH: Gauge = register_gauge!(
        "kelan_sentinel_channel_depth",
        "Number of events pending in the Sentinel channel"
    ).unwrap();

    /// Anomaly detection latency (event-driven path)
    pub static ref ANOMALY_DETECTION_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_anomaly_detection_ms",
        "Time from session event to anomaly detection in milliseconds",
        &["signal_type"],  // critical | elevated | routine
        vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0, 500.0]
    ).unwrap();

    /// Entities currently quarantined
    pub static ref QUARANTINED_ENTITIES: Gauge = register_gauge!(
        "kelan_quarantined_entities",
        "Number of entities currently quarantined"
    ).unwrap();

    // ── Threat Response ───────────────────────────────────────────────────

    /// Security incidents by severity
    pub static ref THREAT_INCIDENTS: CounterVec = register_counter_vec!(
        "kelan_threat_incidents_total",
        "Security incidents detected by the Threat Response agent",
        &["severity", "attack_type"]
    ).unwrap();

    /// Threat Response agent steps per investigation
    pub static ref THREAT_AGENT_STEPS: HistogramVec = register_histogram_vec!(
        "kelan_threat_agent_steps",
        "ReAct loop steps taken per threat investigation",
        &["outcome"],   // quarantined | alerted | false_positive
        vec![1.0, 3.0, 5.0, 8.0, 10.0, 15.0, 20.0]
    ).unwrap();

    // ── WebSocket Hub ────────────────────────────────────────────────────

    /// Connected WebSocket subscribers (dashboard connections)
    pub static ref WS_SUBSCRIBERS: Gauge = register_gauge!(
        "kelan_ws_subscribers",
        "Number of connected WebSocket dashboard subscribers"
    ).unwrap();

    /// WebSocket events broadcast
    pub static ref WS_EVENTS: CounterVec = register_counter_vec!(
        "kelan_ws_events_total",
        "WebSocket events broadcast to dashboard subscribers",
        &["event_type"]
    ).unwrap();

    // ── Database ──────────────────────────────────────────────────────────

    /// DB query latency
    pub static ref DB_QUERY_LATENCY: HistogramVec = register_histogram_vec!(
        "kelan_db_query_ms",
        "Database query latency in milliseconds",
        &["operation"],  // select | insert | update | delete
        vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0]
    ).unwrap();

    /// DB pool connections
    pub static ref DB_POOL_CONNECTIONS: GaugeVec = register_gauge_vec!(
        "kelan_db_pool_connections",
        "Database connection pool state",
        &["state"]   // active | idle | waiting
    ).unwrap();

    // ── Business / Licensing ──────────────────────────────────────────────

    /// Registered entities per org
    pub static ref REGISTERED_ENTITIES: GaugeVec = register_gauge_vec!(
        "kelan_registered_entities",
        "Number of entities registered per organisation",
        &["org_id", "tier"]
    ).unwrap();

    /// License node limit utilisation (0.0 - 1.0)
    pub static ref LICENSE_UTILISATION: GaugeVec = register_gauge_vec!(
        "kelan_license_utilisation",
        "License node limit utilisation ratio (current/max)",
        &["org_id", "tier"]
    ).unwrap();
}

/// Handler for GET /metrics — returns Prometheus text format
pub async fn metrics_handler() -> impl axum::response::IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        buffer,
    )
}

/// Helper: record a session evaluation result
pub fn record_session(verdict: &str, intent: &str, org_id: &str,
                      latency_ms: f64, trust_score: u8, trust_mode: &str) {
    SESSIONS_TOTAL
        .with_label_values(&[verdict, intent, org_id])
        .inc();
    HANDSHAKE_LATENCY
        .with_label_values(&[trust_mode])
        .observe(latency_ms);
    TRUST_SCORE
        .with_label_values(&[verdict])
        .observe(trust_score as f64);
}

/// Helper: record a Gemini API call
pub fn record_gemini_call(model: &str, outcome: &str, latency_ms: f64) {
    GEMINI_LATENCY
        .with_label_values(&[model, outcome])
        .observe(latency_ms);
    if outcome != "success" {
        GEMINI_ERRORS
            .with_label_values(&[outcome])
            .inc();
    }
}


