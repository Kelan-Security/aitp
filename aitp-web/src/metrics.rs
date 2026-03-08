use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use lazy_static::lazy_static;
use prometheus::{
    opts, register_counter, register_gauge, register_histogram, Counter, Encoder, Gauge, Histogram,
    TextEncoder,
};
use std::sync::Arc;

lazy_static! {
    pub static ref METRIC_SESSIONS_ACTIVE: Gauge = register_gauge!(opts!(
        "aitp_sessions_active",
        "Number of currently active sessions"
    ))
    .unwrap();
    pub static ref METRIC_SESSIONS_TOTAL: Gauge =
        register_gauge!(opts!("aitp_sessions_total", "Total sessions processed")).unwrap();
    pub static ref METRIC_SESSIONS_BLOCKED: Gauge = register_gauge!(opts!(
        "aitp_sessions_blocked",
        "Total sessions blocked by security policy"
    ))
    .unwrap();
    pub static ref METRIC_TRUST_EVAL_LATENCY: Histogram = register_histogram!(
        "aitp_trust_evaluation_latency_ms",
        "Latency of trust evaluations in ms",
        vec![5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
    )
    .unwrap();
    pub static ref METRIC_AI_CALLS_TOTAL: Gauge = register_gauge!(opts!(
        "aitp_ai_calls_total",
        "Total AI evaluation calls made"
    ))
    .unwrap();
    pub static ref METRIC_ANOMALIES_DETECTED: Counter = register_counter!(opts!(
        "aitp_anomalies_detected",
        "Total behavioral anomalies detected by Sentinel"
    ))
    .unwrap();
    pub static ref METRIC_BYTES_TX: Counter = register_counter!(opts!(
        "aitp_network_bytes_tx",
        "Total bytes transmitted over sessions"
    ))
    .unwrap();
    pub static ref METRIC_BYTES_RX: Counter = register_counter!(opts!(
        "aitp_network_bytes_rx",
        "Total bytes received over sessions"
    ))
    .unwrap();
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Update active stats from DB before returning
    if let Ok(stats) = state.db.get_stats(0).await {
        METRIC_SESSIONS_ACTIVE.set(stats.active_sessions as f64);
        METRIC_SESSIONS_TOTAL.set(stats.total_sessions as f64);
        METRIC_SESSIONS_BLOCKED.set(stats.blocked_today as f64);
        METRIC_AI_CALLS_TOTAL.set(stats.ai_calls_today as f64);

        if let Some(avg_lat) = stats.avg_ai_latency_ms {
            METRIC_TRUST_EVAL_LATENCY.observe(avg_lat);
        }
    }

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to encode metrics: {}", e),
        ));
    }

    match String::from_utf8(buffer) {
        Ok(metrics_text) => Ok(metrics_text),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to convert metrics to UTF8: {}", e),
        )),
    }
}
