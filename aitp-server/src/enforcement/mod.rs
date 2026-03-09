pub mod ebpf;
pub mod software;

/// Trait for transport-layer enforcement.
pub trait EnforcementPlane: Send + Sync {
    /// Install a session permit (allow traffic).
    fn install_permit(&self, session_id: &str, source_ip: &str, dest_ip: &str) -> bool;

    /// Revoke a specific session permit.
    fn revoke_permit(&self, session_id: &str) -> bool;

    /// Revoke all permits for an entity.
    fn revoke_all_for_entity(&self, entity_id: &str) -> u32;

    /// Check if a session has an active permit.
    fn has_permit(&self, session_id: &str) -> bool;

    /// Name of this enforcement backend.
    fn name(&self) -> &'static str;
}

/// Select the appropriate enforcement backend.
pub fn select_backend() -> Box<dyn EnforcementPlane> {
    if cfg!(target_os = "linux") {
        tracing::info!("eBPF enforcement available (Linux detected)");
        // On Linux, could use eBPF — but for now always use software fallback
        Box::new(software::SoftwareEnforcement::new())
    } else {
        tracing::info!("Using software enforcement (non-Linux platform)");
        Box::new(software::SoftwareEnforcement::new())
    }
}
