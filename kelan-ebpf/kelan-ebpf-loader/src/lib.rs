use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(not(target_os = "linux"))]
pub mod userspace;
#[cfg(not(target_os = "linux"))]
pub use userspace::BpfEnforcer;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::BpfEnforcer;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionPermit {
    pub source_entity_prefix: [u8; 8],
    pub dest_entity_prefix: [u8; 8],
    pub intent: u16,
    pub trust_score: u8,
    pub verdict: u8,
    pub expires_at: u64,
    pub _pad: [u8; 4],
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for SessionPermit {}

impl SessionPermit {
    pub fn new(
        source_entity_id: &[u8; 32],
        dest_entity_id: &[u8; 32],
        intent: u16,
        trust_score: u8,
        verdict: u8,
        ttl_seconds: u64,
    ) -> Self {
        let mut src = [0u8; 8];
        let mut dst = [0u8; 8];
        src.copy_from_slice(&source_entity_id[..8]);
        dst.copy_from_slice(&dest_entity_id[..8]);

        Self {
            source_entity_prefix: src,
            dest_entity_prefix: dst,
            intent,
            trust_score,
            verdict,
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + ttl_seconds,
            _pad: [0; 4],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EnforcerStats {
    pub packets_total: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub packets_bypassed: u64,
    pub active_permits: usize,
    pub mode: EnforcerMode,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum EnforcerMode {
    #[default]
    Software,
    BpfXdp {
        interface: String,
    },
}

#[async_trait::async_trait]
pub trait NetworkEnforcer: Send + Sync {
    async fn attach(&self, interface: &str) -> anyhow::Result<()>;
    async fn permit(&self, session_id: u64, permit: SessionPermit) -> anyhow::Result<()>;
    async fn revoke(&self, session_id: u64) -> anyhow::Result<()>;
    async fn revoke_entity(&self, entity_id_prefix: &[u8; 8]) -> anyhow::Result<u32>;
    async fn stats(&self) -> anyhow::Result<EnforcerStats>;
    fn mode(&self) -> EnforcerMode;
    /// Remove expired session permits from kernel maps (no-op in software mode).
    async fn cleanup_expired_sessions(&self) -> anyhow::Result<()> {
        Ok(()) // Default implementation — override on Linux eBPF path
    }
}
