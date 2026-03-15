// Kernex Client Agent — interceptor/iptables.rs
// iptables-based transparent interception — Linux only, requires root.

#[cfg(target_os = "linux")]
pub struct IptablesInterceptor {
    proxy_port: u16,
    uid: u32,
}

#[cfg(target_os = "linux")]
impl IptablesInterceptor {
    pub fn new(proxy_port: u16) -> anyhow::Result<Self> {
        let uid = nix::unistd::getuid().as_raw();
        Ok(Self { proxy_port, uid })
    }

    /// Install iptables rules. Called at daemon startup.
    pub fn install(&self) -> anyhow::Result<()> {
        let ipt = iptables::new(false)?;

        // Create KERNEX chain
        let _ = ipt.new_chain("nat", "KERNEX");

        // Exclude traffic from the proxy itself (prevent loop)
        ipt.append(
            "nat",
            "KERNEX",
            &format!("-m owner --uid-owner {} -j RETURN", self.uid),
        )?;

        // Exclude loopback
        ipt.append("nat", "KERNEX", "-d 127.0.0.0/8 -j RETURN")?;

        // Exclude Intelligence Core traffic (prevent loop)
        ipt.append("nat", "KERNEX", "--dport 9999 -j RETURN")?;
        ipt.append("nat", "KERNEX", "--dport 3000 -j RETURN")?;

        // Exclude DNS and SSH
        ipt.append("nat", "KERNEX", "--dport 53 -j RETURN")?;
        ipt.append("nat", "KERNEX", "--dport 22 -j RETURN")?;

        // Redirect everything else to our SOCKS5 proxy
        ipt.append(
            "nat",
            "KERNEX",
            &format!("-p tcp -j REDIRECT --to-ports {}", self.proxy_port),
        )?;

        // Jump to KERNEX chain from OUTPUT
        ipt.insert("nat", "OUTPUT", "-p tcp -j KERNEX", 1)?;

        tracing::info!("iptables rules installed (proxy_port={})", self.proxy_port);
        Ok(())
    }

    /// Remove iptables rules. Called at daemon shutdown.
    pub fn remove(&self) -> anyhow::Result<()> {
        let ipt = iptables::new(false)?;
        let _ = ipt.delete("nat", "OUTPUT", "-p tcp -j KERNEX");
        let _ = ipt.flush_chain("nat", "KERNEX");
        let _ = ipt.delete_chain("nat", "KERNEX");
        tracing::info!("iptables rules removed");
        Ok(())
    }
}
