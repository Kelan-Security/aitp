// AITP Client Agent — config.rs
// Loads configuration from aitp-client.toml with env var overrides.

use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub tls: bool,
    pub certificate_path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "localhost".into(),
            port: 3000,
            tls: false,
            certificate_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub entity_name: String,
    pub entity_type: String,
    pub department: String,
    pub clearance_level: u8,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            entity_name: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown-device".into()),
            entity_type: "workstation".into(),
            department: String::new(),
            clearance_level: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionConfig {
    pub mode: String,
    pub exclude_ports: Vec<u16>,
}

impl Default for InterceptionConfig {
    fn default() -> Self {
        Self {
            mode: "none".into(),
            exclude_ports: vec![22, 53],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub log_file: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            log_file: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    pub server: ServerConfig,
    pub agent: AgentConfig,
    pub interception: InterceptionConfig,
    pub logging: LoggingConfig,
}

impl ClientConfig {
    /// Load configuration from file, falling back to defaults.
    pub fn load() -> Result<Self> {
        let config_path = Self::default_config_path();

        let mut config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            toml::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        };

        // Environment variable overrides
        if let Ok(addr) = std::env::var("AITP_SERVER_ADDRESS") {
            config.server.address = addr;
        }
        if let Ok(port) = std::env::var("AITP_SERVER_PORT") {
            config.server.port = port.parse().unwrap_or(config.server.port);
        }
        if let Ok(mode) = std::env::var("AITP_MODE") {
            config.interception.mode = mode;
        }
        if let Ok(level) = std::env::var("AITP_LOG_LEVEL") {
            config.logging.level = level;
        }

        Ok(config)
    }

    /// Save configuration to the default path.
    pub fn save(&self) -> Result<()> {
        let path = Self::default_config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn default_config_path() -> PathBuf {
        if let Some(proj_dirs) = ProjectDirs::from("dev", "aitp", "aitp-client") {
            proj_dirs.config_dir().join("aitp-client.toml")
        } else {
            PathBuf::from("aitp-client.toml")
        }
    }

    pub fn api_base_url(&self) -> String {
        let scheme = if self.server.tls { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.server.address, self.server.port)
    }
}

// Tiny helper to get hostname without an extra dep in most of the codebase
mod hostname {
    pub fn get() -> Result<std::ffi::OsString, ()> {
        std::env::var_os("HOSTNAME")
            .or_else(|| std::env::var_os("COMPUTERNAME"))
            .ok_or(())
    }
}
