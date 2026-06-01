// Kelan Security Client Agent — interceptor/iptables.rs
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
        let ipt = iptables::new(false)
            .map_err(|e| anyhow::anyhow!("iptables init failed: {}", e))?;

        // Create KELAN chain
        let _ = ipt.new_chain("nat", "KELAN");

        // Exclude traffic from the proxy itself (prevent loop)
        ipt.append(
            "nat",
            "KELAN",
            &format!("-m owner --uid-owner {} -j RETURN", self.uid),
        ).map_err(|e| anyhow::anyhow!("iptables append failed: {}", e))?;

        // Exclude loopback
        ipt.append("nat", "KELAN", "-d 127.0.0.0/8 -j RETURN")
            .map_err(|e| anyhow::anyhow!("iptables append failed: {}", e))?;

        // Exclude Intelligence Core traffic (prevent loop)
        ipt.append("nat", "KELAN", "--dport 9999 -j RETURN")
            .map_err(|e| anyhow::anyhow!("iptables append failed: {}", e))?;
        ipt.append("nat", "KELAN", "--dport 3000 -j RETURN")
            .map_err(|e| anyhow::anyhow!("iptables append failed: {}", e))?;

        // Exclude DNS and SSH
        ipt.append("nat", "KELAN", "--dport 53 -j RETURN")
            .map_err(|e| anyhow::anyhow!("iptables append failed: {}", e))?;
        ipt.append("nat", "KELAN", "--dport 22 -j RETURN")
            .map_err(|e| anyhow::anyhow!("iptables append failed: {}", e))?;

        // Redirect everything else to our SOCKS5 proxy
        ipt.append(
            "nat",
            "KELAN",
            &format!("-p tcp -j REDIRECT --to-ports {}", self.proxy_port),
        ).map_err(|e| anyhow::anyhow!("iptables append failed: {}", e))?;

        // Jump to KELAN chain from OUTPUT
        ipt.insert("nat", "OUTPUT", "-p tcp -j KELAN", 1)
            .map_err(|e| anyhow::anyhow!("iptables insert failed: {}", e))?;

        tracing::info!("iptables rules installed (proxy_port={})", self.proxy_port);
        Ok(())
    }

    /// Remove iptables rules. Called at daemon shutdown.
    pub fn remove(&self) -> anyhow::Result<()> {
        let ipt = iptables::new(false)
            .map_err(|e| anyhow::anyhow!("iptables init failed: {}", e))?;
        let _ = ipt.delete("nat", "OUTPUT", "-p tcp -j KELAN");
        let _ = ipt.flush_chain("nat", "KELAN");
        let _ = ipt.delete_chain("nat", "KELAN");
        tracing::info!("iptables rules removed");
        Ok(())
    }
}
