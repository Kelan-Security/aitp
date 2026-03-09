use serde::{Deserialize, Serialize};

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub token_config: crate::auth::TokenConfig,
    pub http_port: u16,
    pub udp_port: u16,
    pub db_path: String,
    pub gemini_api_key: String,
    pub gemini_model: String,
    pub trust_mode: String, // "hybrid" | "rules" | "ai_only"
    pub trust_alpha: f64,   // weight for rules vs AI (0.4 = 40% rules)
    pub sentinel_enabled: bool,
    pub sentinel_scan_interval_secs: u64,
    pub auto_quarantine: bool,
    pub log_level: String,
}

impl AppConfig {
    /// Load configuration from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        let token_config = crate::auth::TokenConfig::from_env().unwrap_or_else(|e| {
            panic!("Critical error loading token config: {}", e);
        });

        Self {
            token_config,
            http_port: std::env::var("AITP_HTTP_PORT")
                .unwrap_or_else(|_| "3000".into())
                .parse()
                .unwrap_or(3000),
            udp_port: std::env::var("AITP_UDP_PORT")
                .unwrap_or_else(|_| "9999".into())
                .parse()
                .unwrap_or(9999),
            db_path: std::env::var("AITP_DB_PATH").unwrap_or_else(|_| "./data/aitp.db".into()),
            gemini_api_key: std::env::var("GEMINI_API_KEY").unwrap_or_else(|_| String::new()),
            gemini_model: std::env::var("AITP_GEMINI_MODEL")
                .unwrap_or_else(|_| "gemini-2.5-flash-preview-05-20".into()),
            trust_mode: std::env::var("AITP_TRUST_MODE").unwrap_or_else(|_| "hybrid".into()),
            trust_alpha: std::env::var("AITP_TRUST_ALPHA")
                .unwrap_or_else(|_| "0.4".into())
                .parse()
                .unwrap_or(0.4),
            sentinel_enabled: std::env::var("AITP_SENTINEL_ENABLED")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            sentinel_scan_interval_secs: std::env::var("AITP_SENTINEL_SCAN_INTERVAL_SECS")
                .unwrap_or_else(|_| "30".into())
                .parse()
                .unwrap_or(30),
            auto_quarantine: std::env::var("AITP_AUTO_QUARANTINE")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            log_level: std::env::var("AITP_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        }
    }

    /// Print a summary of the configuration (masking secrets).
    pub fn summary(&self) -> String {
        format!(
            "HTTP={} UDP={} DB={} Trust={} Alpha={:.1} Sentinel={} AutoQ={} Gemini={}",
            self.http_port,
            self.udp_port,
            self.db_path,
            self.trust_mode,
            self.trust_alpha,
            self.sentinel_enabled,
            self.auto_quarantine,
            if self.gemini_api_key.is_empty() {
                "not configured"
            } else {
                "configured"
            },
        )
    }
}
