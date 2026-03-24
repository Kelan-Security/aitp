pub use kelan_ebpf_loader::{BpfEnforcer, EnforcerMode, SessionPermit};

pub async fn init_enforcer(interface: &str) -> anyhow::Result<BpfEnforcer> {
    match BpfEnforcer::new(interface).await {
        Ok(enforcer) => {
            match &enforcer.mode {
                EnforcerMode::EbpfXdp { interface } => {
                    tracing::info!(
                        "eBPF XDP enforcement active on interface '{}'",
                        interface
                    );
                    tracing::info!(
                        "Session revocation latency: < 1μs (kernel driver level)"
                    );
                    // Record XDP mode = 1 in Prometheus
                    crate::metrics::EBPF_MODE
                        .with_label_values(&[interface.as_str()])
                        .set(1.0);
                }
                EnforcerMode::Software => {
                    tracing::warn!(
                        "Software enforcement mode (application layer)."
                    );
                    tracing::warn!(
                        "For kernel-level enforcement: run on Linux 5.15+ as root"
                    );
                    // Record software mode = 0 in Prometheus
                    crate::metrics::EBPF_MODE
                        .with_label_values(&["software"])
                        .set(0.0);
                }
            }
            Ok(enforcer)
        }
        Err(e) => {
            tracing::warn!("eBPF init failed ({}), falling back to software", e);
            crate::metrics::EBPF_MODE
                .with_label_values(&["software"])
                .set(0.0);
            BpfEnforcer::new("software-fallback").await
        }
    }
}
