// Kernex Client Agent — config.rs
// AgentConfig loaded from kernex-agent.toml with env var overrides.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentConfig {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub agent: AgentIdentityConfig,

    #[serde(default)]
    pub interception: InterceptionConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    /// Intelligence Core address — hostname or IP
    pub address: String,
    /// REST API port (default 3000)
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    /// AITP UDP port (default 9999)
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
    /// Use TLS for API connection
    #[serde(default)]
    pub tls: bool,
    /// Path to custom CA certificate (for self-signed certs)
    pub ca_cert_path: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "localhost".to_string(),
            api_port: 3000,
            udp_port: 9999,
            tls: false,
            ca_cert_path: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentIdentityConfig {
    /// Human-readable name for this device (auto-detected if empty)
    #[serde(default)]
    pub entity_name: String,
    /// Entity type
    #[serde(default = "default_entity_type")]
    pub entity_type: String,
    /// Department
    pub department: Option<String>,
    /// Clearance level 0-3
    #[serde(default)]
    pub clearance_level: u8,
    /// JWT token for authenticating with the Intelligence Core API
    pub api_token: Option<String>,
    /// Organisation ID (set during enrolment)
    pub org_id: Option<String>,
}

impl Default for AgentIdentityConfig {
    fn default() -> Self {
        Self {
            entity_name: String::new(),
            entity_type: default_entity_type(),
            department: None,
            clearance_level: 0,
            api_token: None,
            org_id: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InterceptionConfig {
    /// Interception mode
    #[serde(default = "default_mode")]
    pub mode: InterceptionMode,
    /// Local SOCKS5 proxy port (proxy mode only)
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Ports to exclude from interception
    #[serde(default = "default_exclude_ports")]
    pub exclude_ports: Vec<u16>,
    /// Hosts/IPs to exclude
    #[serde(default)]
    pub exclude_hosts: Vec<String>,
    /// If true: deny connections when Intelligence Core is unreachable
    #[serde(default = "default_true")]
    pub fail_closed: bool,
}

impl Default for InterceptionConfig {
    fn default() -> Self {
        Self {
            mode: InterceptionMode::Proxy,
            proxy_port: 7654,
            exclude_ports: default_exclude_ports(),
            exclude_hosts: Vec::new(),
            fail_closed: true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum InterceptionMode {
    /// Local SOCKS5 proxy — cross-platform, no root needed
    Proxy,
    /// iptables REDIRECT — Linux only, requires root/CAP_NET_ADMIN
    Iptables,
    /// Monitor-only — no blocking, just log what would happen
    Monitor,
}

impl std::fmt::Display for InterceptionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proxy => write!(f, "proxy"),
            Self::Iptables => write!(f, "iptables"),
            Self::Monitor => write!(f, "monitor"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log file path (empty = stderr only)
    #[serde(default)]
    pub file: String,
    /// Log in JSON format
    #[serde(default)]
    pub json: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: String::new(),
            json: false,
        }
    }
}

// ── default functions ──
fn default_api_port() -> u16 { 3000 }
fn default_udp_port() -> u16 { 9999 }
fn default_proxy_port() -> u16 { 7654 }
fn default_entity_type() -> String { "workstation".to_string() }
fn default_mode() -> InterceptionMode { InterceptionMode::Proxy }
fn default_log_level() -> String { "info".to_string() }
fn default_true() -> bool { true }
fn default_exclude_ports() -> Vec<u16> { vec![22, 53, 123] }

impl AgentConfig {
    /// Load from file, fall back to defaults + env overrides
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let mut config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str(&content)?
        } else {
            Self::default()
        };

        // Environment variable overrides
        if let Ok(addr) = std::env::var("KERNEX_SERVER_ADDRESS") {
            config.server.address = addr;
        }
        if let Ok(port) = std::env::var("KERNEX_SERVER_PORT") {
            if let Ok(p) = port.parse() {
                config.server.api_port = p;
            }
        }
        if let Ok(token) = std::env::var("KERNEX_API_TOKEN") {
            config.agent.api_token = Some(token);
        }

        Ok(config)
    }

    /// Intelligence Core base URL
    pub fn ic_url(&self) -> String {
        let scheme = if self.server.tls { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.server.address, self.server.api_port)
    }

    /// WebSocket URL for command channel
    pub fn ws_url(&self, token: &str) -> String {
        let scheme = if self.server.tls { "wss" } else { "ws" };
        format!(
            "{}://{}:{}/ws?token={}",
            scheme, self.server.address, self.server.api_port, token
        )
    }

    /// Default config path
    #[allow(dead_code)]
    pub fn default_config_path() -> std::path::PathBuf {
        std::path::PathBuf::from("/etc/kernex/kernex-agent.toml")
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            agent: AgentIdentityConfig::default(),
            interception: InterceptionConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.server.address, "localhost");
        assert_eq!(config.server.api_port, 3000);
        assert_eq!(config.interception.mode, InterceptionMode::Proxy);
        assert_eq!(config.interception.proxy_port, 7654);
        assert!(config.interception.fail_closed);
    }

    #[test]
    fn test_ic_url() {
        let config = AgentConfig::default();
        assert_eq!(config.ic_url(), "http://localhost:3000");
    }

    #[test]
    fn test_interception_mode_display() {
        assert_eq!(InterceptionMode::Proxy.to_string(), "proxy");
        assert_eq!(InterceptionMode::Iptables.to_string(), "iptables");
        assert_eq!(InterceptionMode::Monitor.to_string(), "monitor");
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = AgentConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AgentConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.server.api_port, 3000);
    }
}
