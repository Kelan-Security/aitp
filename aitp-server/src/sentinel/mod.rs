pub mod anomaly;
pub mod baseline;
pub mod threat;

use crate::state::AppState;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration};

pub use anomaly::{Anomaly, AnomalySeverity, AnomalyType};
pub use baseline::EntityBaseline;
pub use threat::SecurityIncident;

/// The Sentinel — autonomous network defense agent.
pub struct Sentinel {
    pub baselines: RwLock<HashMap<String, EntityBaseline>>,
    pub anomalies: Mutex<VecDeque<Anomaly>>, // ring buffer, last 1000
    pub incidents: Mutex<Vec<SecurityIncident>>,
}

impl Sentinel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            baselines: RwLock::new(HashMap::new()),
            anomalies: Mutex::new(VecDeque::with_capacity(1000)),
            incidents: Mutex::new(Vec::new()),
        })
    }
}

/// Run Sentinel in background — spawned from main.rs.
pub async fn run(state: Arc<AppState>, sentinel: Arc<Sentinel>) {
    let mut baseline_tick = interval(Duration::from_secs(60));
    let mut anomaly_tick = interval(Duration::from_secs(
        state.config.sentinel_scan_interval_secs,
    ));
    let mut threat_tick = interval(Duration::from_secs(5));
    let mut report_tick = interval(Duration::from_secs(3600));

    state.hub.log(
        "AI",
        "AITP Sentinel v0.3 starting — autonomous network defense",
    );
    state.hub.log(
        "AI",
        "Sentinel: learning mode ACTIVE — baseline collection begins",
    );

    loop {
        tokio::select! {
            _ = baseline_tick.tick() => {
                baseline::update_baselines(&state, &sentinel).await;
            }
            _ = anomaly_tick.tick() => {
                anomaly::scan_anomalies(&state, &sentinel).await;
            }
            _ = threat_tick.tick() => {
                anomaly::check_critical_anomalies(&state, &sentinel).await;
            }
            _ = report_tick.tick() => {
                generate_hourly_report(&state, &sentinel).await;
            }
        }
    }
}

async fn generate_hourly_report(state: &Arc<AppState>, sentinel: &Arc<Sentinel>) {
    let anomalies = sentinel.anomalies.lock().await;
    let critical = anomalies
        .iter()
        .filter(|a| matches!(a.severity, AnomalySeverity::Critical))
        .count();
    let alerts = anomalies
        .iter()
        .filter(|a| matches!(a.severity, AnomalySeverity::Alert))
        .count();
    let entities = sentinel.baselines.read().await.len();

    state.hub.log(
        "AI",
        &format!(
            "Sentinel hourly report: {} critical  {} alerts  {} entities monitored",
            critical, alerts, entities
        ),
    );
}
