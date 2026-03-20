// Kelan Security Client Agent — interceptor/mod.rs
// Connection interception modes: SOCKS5 proxy, iptables, monitor.

pub mod proxy;
pub mod monitor;

#[cfg(target_os = "linux")]
pub mod iptables;

use crate::config::{AgentConfig, InterceptionMode};
use crate::identity::EntityIdentity;
use crate::session::SessionTable;
use std::sync::Arc;

/// Start the appropriate interceptor based on config.
pub async fn start(
    config: Arc<AgentConfig>,
    identity: Arc<EntityIdentity>,
    sessions: SessionTable,
) -> anyhow::Result<()> {
    match config.interception.mode {
        InterceptionMode::Proxy => {
            proxy::run_socks5_proxy(config, identity, sessions).await
        }
        InterceptionMode::Iptables => {
            #[cfg(target_os = "linux")]
            {
                // Install iptables rules then run the proxy
                let ipt = iptables::IptablesInterceptor::new(config.interception.proxy_port)?;
                ipt.install()?;

                // Run proxy (iptables redirects to it)
                let result = proxy::run_socks5_proxy(config, identity, sessions).await;

                // Clean up iptables on shutdown
                let _ = ipt.remove();
                result
            }
            #[cfg(not(target_os = "linux"))]
            {
                tracing::warn!("iptables mode is Linux-only — falling back to proxy mode");
                proxy::run_socks5_proxy(config, identity, sessions).await
            }
        }
        InterceptionMode::Monitor => {
            monitor::run_monitor(config).await
        }
    }
}
