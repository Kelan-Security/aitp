use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(not(target_os = "linux"))]
pub use software::BpfEnforcer;

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
    BpfXdp { interface: String },
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use aya::{
        maps::HashMap,
        programs::{Xdp, XdpFlags},
        Bpf,
    };
    use std::collections::HashMap as StdHashMap;

    #[cfg(target_os = "linux")]
    static KERNEX_XDP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kelan_xdp.o"));

    pub struct BpfEnforcer {
        _bpf: Arc<RwLock<Bpf>>,
        permit_map: Arc<RwLock<HashMap<aya::maps::MapData, u64, super::SessionPermit>>>,
        active_permits: Arc<RwLock<StdHashMap<u64, super::SessionPermit>>>,
        interface: String,
        pub mode: super::EnforcerMode,
    }

    impl BpfEnforcer {
        pub async fn new(interface: &str) -> anyhow::Result<Self> {
            if KERNEX_XDP_BYTES.is_empty() {
                anyhow::bail!(
                    "BPF program not compiled (bpf-linker not available). \
                     Using software enforcement. \
                     Install bpf-linker for kernel-level enforcement."
                );
            }

            if !Self::has_cap_net_admin() {
                anyhow::bail!("CAP_NET_ADMIN required for BPF XDP.");
            }

            if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
                anyhow::bail!("Kernel BTF not available.");
            }

            tracing::info!("Loading BPF XDP program onto interface: {}", interface);

            let mut bpf = Bpf::load(KERNEX_XDP_BYTES)
                .map_err(|e| anyhow::anyhow!("Failed to load BPF program: {}", e))?;

            if let Err(e) = aya_log::BpfLogger::init(&mut bpf) {
                tracing::warn!("BPF logger init failed (non-fatal): {}", e);
            }

            let program: &mut Xdp = bpf
                .program_mut("kelan_xdp")
                .ok_or_else(|| anyhow::anyhow!("BPF program 'kelan_xdp' not found"))?
                .try_into()?;

            program.load()?;

            let flags = if Self::interface_supports_native_xdp(interface) {
                XdpFlags::default()
            } else {
                XdpFlags::SKB_MODE
            };

            program.attach(interface, flags)
                .map_err(|e| anyhow::anyhow!("Failed to attach XDP to {}: {}", interface, e))?;

            let permit_map_data = bpf.take_map("PERMIT_MAP")
                .ok_or_else(|| anyhow::anyhow!("PERMIT_MAP not found in BPF object"))?;
            let permit_map = HashMap::try_from(permit_map_data)?;

            let bpf_arc = Arc::new(RwLock::new(bpf));
            let permit_map_arc = Arc::new(RwLock::new(permit_map));
            let active_permits_arc = Arc::new(RwLock::new(StdHashMap::new()));

            let pm_clone = Arc::clone(&permit_map_arc);
            let ap_clone = Arc::clone(&active_permits_arc);
            tokio::spawn(Self::expiry_cleanup_task(pm_clone, ap_clone));

            Ok(Self {
                _bpf: bpf_arc,
                permit_map: permit_map_arc,
                active_permits: active_permits_arc,
                interface: interface.to_string(),
                mode: super::EnforcerMode::BpfXdp {
                    interface: interface.to_string(),
                },
            })
        }

        pub async fn permit(&self, session_id: u64, permit: super::SessionPermit) -> anyhow::Result<()> {
            {
                let mut map = self.permit_map.write().await;
                map.insert(session_id, permit, 0)
                    .map_err(|e| anyhow::anyhow!("BPF map insert failed: {}", e))?;
            }
            {
                let mut active = self.active_permits.write().await;
                active.insert(session_id, permit);
            }
            Ok(())
        }

        pub async fn revoke(&self, session_id: u64) -> anyhow::Result<()> {
            {
                let mut map = self.permit_map.write().await;
                let _ = map.remove(&session_id);
            }
            {
                let mut active = self.active_permits.write().await;
                active.remove(&session_id);
            }
            Ok(())
        }

        pub async fn revoke_entity(&self, entity_id_prefix: &[u8; 8]) -> anyhow::Result<u32> {
            let to_revoke: Vec<u64> = {
                let active = self.active_permits.read().await;
                active
                    .iter()
                    .filter(|(_, p)| &p.source_entity_prefix == entity_id_prefix)
                    .map(|(id, _)| *id)
                    .collect()
            };
            let count = to_revoke.len() as u32;
            for session_id in to_revoke {
                self.revoke(session_id).await?;
            }
            Ok(count)
        }

        pub async fn stats(&self) -> anyhow::Result<super::EnforcerStats> {
            let bpf = self._bpf.read().await;
            let stats_map: aya::maps::HashMap<&aya::maps::MapData, u32, u64> = HashMap::try_from(
                bpf.map("STATS_MAP")
                    .ok_or_else(|| anyhow::anyhow!("STATS_MAP not found"))?,
            )?;
            let active = self.active_permits.read().await;
            Ok(super::EnforcerStats {
                packets_total: stats_map.get(&0, 0).unwrap_or(0),
                packets_passed: stats_map.get(&1, 0).unwrap_or(0),
                packets_dropped: stats_map.get(&2, 0).unwrap_or(0),
                packets_bypassed: stats_map.get(&3, 0).unwrap_or(0),
                active_permits: active.len(),
                mode: self.mode.clone(),
            })
        }

        fn has_cap_net_admin() -> bool {
            std::fs::read_to_string("/proc/self/status")
                .map(|s| s.contains("CapEff:") && !s.contains("CapEff:\t0000000000000000"))
                .unwrap_or(false)
        }

        fn interface_supports_native_xdp(iface: &str) -> bool {
            let known_native = ["eth0", "ens3", "ens4", "enp0s3", "enp0s8"];
            known_native.contains(&iface)
        }

        async fn expiry_cleanup_task(
            permit_map: Arc<RwLock<HashMap<aya::maps::MapData, u64, super::SessionPermit>>>,
            active_permits: Arc<RwLock<StdHashMap<u64, super::SessionPermit>>>,
        ) {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let expired: Vec<u64> = {
                    let active = active_permits.read().await;
                    active
                        .iter()
                        .filter(|(_, p)| p.expires_at > 0 && p.expires_at < now)
                        .map(|(id, _)| *id)
                        .collect()
                };
                if !expired.is_empty() {
                    let mut map = permit_map.write().await;
                    let mut active = active_permits.write().await;
                    for id in expired {
                        let _ = map.remove(&id);
                        active.remove(&id);
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod software {
    use super::*;
    use std::collections::HashMap;

    pub struct BpfEnforcer {
        permits: Arc<RwLock<HashMap<u64, super::SessionPermit>>>,
        pub mode: super::EnforcerMode,
    }

    impl BpfEnforcer {
        pub async fn new(_interface: &str) -> anyhow::Result<Self> {
            tracing::warn!("BPF XDP not available. Using software enforcement.");
            Ok(Self {
                permits: Arc::new(RwLock::new(HashMap::new())),
                mode: super::EnforcerMode::Software,
            })
        }

        pub async fn permit(&self, session_id: u64, p: super::SessionPermit) -> anyhow::Result<()> {
            self.permits.write().await.insert(session_id, p);
            Ok(())
        }

        pub async fn revoke(&self, session_id: u64) -> anyhow::Result<()> {
            self.permits.write().await.remove(&session_id);
            Ok(())
        }

        pub async fn revoke_entity(&self, prefix: &[u8; 8]) -> anyhow::Result<u32> {
            let mut p = self.permits.write().await;
            let before = p.len();
            p.retain(|_, v| &v.source_entity_prefix != prefix);
            Ok((before - p.len()) as u32)
        }

        pub async fn is_permitted(&self, session_id: u64) -> bool {
            let p = self.permits.read().await;
            if let Some(permit) = p.get(&session_id) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                permit.verdict != 0 && (permit.expires_at == 0 || permit.expires_at > now)
            } else {
                false
            }
        }

        pub async fn stats(&self) -> anyhow::Result<super::EnforcerStats> {
            Ok(super::EnforcerStats {
                active_permits: self.permits.read().await.len(),
                mode: self.mode.clone(),
                ..Default::default()
            })
        }
    }
}
