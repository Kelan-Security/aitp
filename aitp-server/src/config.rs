use serde::{Deserialize, Serialize};

use crate::crypto::CryptoAlgorithm;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub token_config: crate::auth::TokenConfig,
    pub http_port: u16,     // AITP_HTTP_PORT, default 3000
    pub https_port: u16,    // AITP_HTTPS_PORT, default 8443
    pub redirect_port: u16, // AITP_REDIRECT_PORT, default 8080
    pub udp_port: u16,
    pub db_path: String,
    pub ollama_endpoint: String,
    pub ollama_model: String,
    pub ollama_timeout_secs: u64,
    pub trust_mode: String, // "hybrid" | "rules" | "ai_only"
    pub trust_alpha: f64,   // weight for rules vs AI (0.4 = 40% rules)
    pub sentinel_enabled: bool,
    pub sentinel_scan_interval_secs: u64,
    pub auto_quarantine: bool,
    pub log_level: String,
    /// Path to TLS certificate PEM file (TLS_CERT_PATH)
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key PEM file (TLS_KEY_PATH)
    pub tls_key_path: Option<String>,
    pub xdp_interface: String,

    /// Minimum cryptographic algorithm clients must use.
    pub min_crypto_algorithm: CryptoAlgorithm,
    /// Advertise PQ support in server hello (clients know to use hybrid)
    pub advertise_pq: bool,
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
            https_port: std::env::var("AITP_HTTPS_PORT")
                .unwrap_or_else(|_| "8443".into())
                .parse()
                .unwrap_or(8443),
            redirect_port: std::env::var("AITP_REDIRECT_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .unwrap_or(8080),
            udp_port: std::env::var("AITP_UDP_PORT")
                .unwrap_or_else(|_| "9999".into())
                .parse()
                .unwrap_or(9999),
            db_path: {
                let raw = std::env::var("DATABASE_URL")
                    .or_else(|_| std::env::var("AITP_DB_PATH"))
                    .unwrap_or_else(|_| "./data/aitp.db".into());
                if !raw.contains("://") {
                    format!("sqlite://{}", raw)
                } else {
                    raw
                }
            },
            ollama_endpoint: std::env::var("OLLAMA_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:11434".into()),
            ollama_model: std::env::var("OLLAMA_MODEL")
                .unwrap_or_else(|_| "gemma3:9b".into()),
            ollama_timeout_secs: std::env::var("OLLAMA_TIMEOUT_SECS")
                .unwrap_or_else(|_| "8".into())
                .parse()
                .unwrap_or(8),
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
            tls_cert_path: std::env::var("TLS_CERT_PATH").ok(),
            tls_key_path: std::env::var("TLS_KEY_PATH").ok(),
            xdp_interface: std::env::var("XDP_INTERFACE").unwrap_or_else(|_| "eth0".into()),
            min_crypto_algorithm: std::env::var("MIN_CRYPTO_ALGORITHM")
                .ok()
                .and_then(|s| match s.as_str() {
                    "Classical" => Some(CryptoAlgorithm::Classical),
                    "HybridPQ" => Some(CryptoAlgorithm::HybridPQ),
                    "PostQuantum" => Some(CryptoAlgorithm::PostQuantum),
                    _ => None,
                })
                .unwrap_or(CryptoAlgorithm::Classical),
            advertise_pq: std::env::var("ADVERTISE_PQ")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
        }
    }

    /// Print a summary of the configuration (masking secrets).
    pub fn summary(&self) -> String {
        let tls = match &self.tls_cert_path {
            Some(_) => "HTTPS PRODUCTION",
            None => "HTTP DEV",
        };
        format!(
            "Mode={} HTTP={} UDP={} DB={} Trust={} Alpha={:.1} Sentinel={} AutoQ={} OllamaEndpoint={}",
            tls,
            self.http_port,
            self.udp_port,
            self.db_path,
            self.trust_mode,
            self.trust_alpha,
            self.sentinel_enabled,
            self.auto_quarantine,
            self.ollama_endpoint,
        )
    }

    /// Returns true when TLS cert+key paths are both configured.
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }
}
