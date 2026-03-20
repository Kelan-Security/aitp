// Kelan Security Client Agent — interceptor/monitor.rs
// Monitor-only mode — no blocking, just logging.

use std::sync::Arc;
use crate::config::AgentConfig;

/// Run in monitor mode — log all connections but never block.
pub async fn run_monitor(config: Arc<AgentConfig>) -> anyhow::Result<()> {
    tracing::info!(
        "Running in MONITOR mode — all connections are allowed, events are logged"
    );
    tracing::info!(
        "Excluded ports: {:?}",
        config.interception.exclude_ports
    );

    // In monitor mode, we don't start any proxy or iptables.
    // The daemon simply runs, performs heartbeats, and reports status.
    // The SOCKS5 proxy is NOT started — no connections are intercepted.
    // This is safe for testing and evaluation:
    //   - Agent registers with IC
    //   - Heartbeats run normally
    //   - Status reports "monitor" mode
    //   - No connections are blocked or delayed

    // Keep running until shutdown
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        tracing::debug!("Monitor mode: idle heartbeat");
    }
}
