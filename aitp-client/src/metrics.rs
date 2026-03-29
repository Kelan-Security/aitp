// Kelan Security Client Agent — metrics.rs
// Local Prometheus metrics for sessions, latency, and blocks.

use prometheus::{Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry};

#[allow(dead_code)]
pub struct AgentMetrics {
    pub registry: Registry,
    pub sessions_total: IntCounter,
    pub sessions_active: IntGauge,
    pub sessions_denied: IntCounter,
    pub handshake_latency: Histogram,
}

#[allow(dead_code)]
impl AgentMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let sessions_total = IntCounter::with_opts(Opts::new(
            "kelan_sessions_total",
            "Total sessions evaluated",
        ))
        .unwrap();

        let sessions_active = IntGauge::with_opts(Opts::new(
            "kelan_sessions_active",
            "Currently active sessions",
        ))
        .unwrap();

        let sessions_denied = IntCounter::with_opts(Opts::new(
            "kelan_sessions_denied",
            "Total sessions denied by IC",
        ))
        .unwrap();

        let handshake_latency = Histogram::with_opts(
            HistogramOpts::new(
                "kelan_handshake_latency_ms",
                "Handshake latency in milliseconds",
            )
            .buckets(vec![
                1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
            ]),
        )
        .unwrap();

        let _ = registry.register(Box::new(sessions_total.clone()));
        let _ = registry.register(Box::new(sessions_active.clone()));
        let _ = registry.register(Box::new(sessions_denied.clone()));
        let _ = registry.register(Box::new(handshake_latency.clone()));

        Self {
            registry,
            sessions_total,
            sessions_active,
            sessions_denied,
            handshake_latency,
        }
    }
}
