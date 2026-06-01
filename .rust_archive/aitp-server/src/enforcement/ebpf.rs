use super::EnforcementPlane;

/// eBPF/XDP enforcement backend.
///
/// On Linux, this would manage an XDP BPF map for kernel-space
/// packet filtering. On other platforms, this is a stub that
/// logs a warning and delegates to the software fallback.
pub struct EbpfEnforcement;

impl EbpfEnforcement {
    #[allow(dead_code)]
    pub fn new() -> Self {
        tracing::warn!(
            "eBPF enforcement requires Linux with BPF support. \
             Use SoftwareEnforcement as fallback."
        );
        Self
    }
}

impl EnforcementPlane for EbpfEnforcement {
    fn install_permit(&self, session_id: &str, _source_ip: &str, _dest_ip: &str) -> bool {
        tracing::debug!(
            "eBPF: install_permit({}) — stub, no-op on this platform",
            session_id
        );
        false
    }

    fn revoke_permit(&self, session_id: &str) -> bool {
        tracing::debug!("eBPF: revoke_permit({}) — stub", session_id);
        false
    }

    fn revoke_all_for_entity(&self, entity_id: &str) -> u32 {
        tracing::debug!("eBPF: revoke_all_for_entity({}) — stub", entity_id);
        0
    }

    fn has_permit(&self, _session_id: &str) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "ebpf_stub"
    }
}
