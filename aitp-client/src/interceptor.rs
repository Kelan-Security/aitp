// AITP Client Agent — interceptor.rs
// Connection interception stub (eBPF/iptables/tun/none modes).

use anyhow::Result;
use tracing::{info, warn};

use crate::config::InterceptionConfig;

pub struct Interceptor {
    config: InterceptionConfig,
}

impl Interceptor {
    pub fn new(config: InterceptionConfig) -> Self {
        Self { config }
    }

    /// Start the connection interceptor based on the configured mode.
    pub async fn start(&self) -> Result<()> {
        match self.config.mode.as_str() {
            "ebpf" => self.start_ebpf().await,
            "iptables" => self.start_iptables().await,
            "tun" => self.start_tun().await,
            "none" | "" => {
                info!("Interception mode: none (monitoring only — connections flow freely)");
                Ok(())
            }
            other => {
                warn!("Unknown interception mode '{}' — falling back to none", other);
                Ok(())
            }
        }
    }

    async fn start_ebpf(&self) -> Result<()> {
        // eBPF program would be loaded here using aya crate (Linux only).
        // The eBPF program attaches to the TC/XDP hook and intercepts outgoing
        // TCP connections, redirecting them to a local UNIX socket where the
        // client daemon performs the AITP handshake.
        //
        // For now we log the intent and fall back to monitoring mode on non-Linux.
        #[cfg(target_os = "linux")]
        {
            warn!("eBPF interception requires root and a compiled BPF program.");
            warn!("Running in monitoring mode until eBPF module is loaded.");
        }
        #[cfg(not(target_os = "linux"))]
        {
            warn!("eBPF interception is Linux-only. Falling back to 'none' mode.");
        }
        Ok(())
    }

    async fn start_iptables(&self) -> Result<()> {
        // iptables redirect: intercept outbound TCP and route through local proxy.
        // Executes: iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 19999
        // (exclude_ports would be handled via --dport exclusions)
        #[cfg(target_os = "linux")]
        {
            warn!("iptables interception requires root.");
            let exclude = self
                .config
                .exclude_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            info!("Excluding ports: {}", exclude);
            warn!("iptables mode: would install NAT rules here. Running in monitoring mode.");
        }
        #[cfg(not(target_os = "linux"))]
        {
            warn!("iptables mode is Linux-only. Falling back to 'none' mode.");
        }
        Ok(())
    }

    async fn start_tun(&self) -> Result<()> {
        // TUN/TAP virtual interface approach — cross-platform alternative.
        // Creates a tun0 interface, sets default route through it,
        // and inspects/proxies all traffic through the AITP handshake.
        warn!("TUN mode: cross-platform approach — would create tun0 interface here.");
        warn!("Running in monitoring mode.");
        Ok(())
    }
}
