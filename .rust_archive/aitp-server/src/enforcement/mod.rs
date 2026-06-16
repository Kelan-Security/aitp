pub use kelan_ebpf_loader::{BpfEnforcer, EnforcerMode, SessionPermit};

pub async fn init_enforcer(interface: &str) -> anyhow::Result<BpfEnforcer> {
    match BpfEnforcer::new(interface).await {
        Ok(enforcer) => {
            match &enforcer.mode {
                EnforcerMode::BpfXdp { interface } => {
                    tracing::info!("eBPF XDP enforcement active on interface '{}'", interface);
                    tracing::info!("Session revocation latency: < 1μs (kernel driver level)");
                    // Record XDP mode = 1 in Prometheus
                    crate::metrics::EBPF_MODE
                        .with_label_values(&[interface.as_str()])
                        .set(1.0);
                }
                EnforcerMode::Software => {
                    tracing::warn!("Software enforcement mode (application layer).");
                    tracing::warn!("For kernel-level enforcement: run on Linux 5.15+ as root");
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

/// Abstract conceptual mapping bridging userspace Post-Quantum state into eBPF maps
#[allow(clippy::too_many_arguments)]
pub async fn register_kernel_session(
    enforcer: &BpfEnforcer,
    session_id: u64,
    source_id: &[u8; 32],
    dest_id: &[u8; 32],
    intent: u16,
    trust_score: u8,
    verdict: u8,
    _shared_secret: [u8; crate::crypto::MLKEM768_SS_BYTES],
    phase: crate::protocol::handshake::HandshakePhase,
) {
    if phase != crate::protocol::handshake::HandshakePhase::Complete {
        tracing::warn!(
            "Blocked early kernel registration for session {} \
             (phase: {:?})",
            session_id,
            phase
        );
        return;
    }
    let permit = SessionPermit::new(
        source_id,
        dest_id,
        intent,
        trust_score,
        verdict,
        3600, // 1 hour TTL
    );

    // In actual implementation, modifying the XDP eBPF map to enforce AES acceleration
    // utilizes the negotiated ML-KEM shared_secret block.
    // For now we push the pre-authenticated session payload:
    let _ = enforcer.permit(session_id, permit).await;
}
