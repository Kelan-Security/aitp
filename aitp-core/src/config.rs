//! TOML-based configuration for the AITP node with environment variable overrides.
//!
//! # Priority order (highest wins)
//!
//! 1. **Environment variables** with `AITP_` prefix (e.g. `AITP_NODE_LISTEN_PORT=9999`)
//! 2. **TOML file** specified via `--config` or default `aitp.toml`
//! 3. **Built-in defaults** for local development
//!
//! # Validation
//!
//! Call [`AitpConfig::validate()`] after loading to check for semantic errors
//! (e.g. Gemini API key required when mode is `gemini`, timeout budget consistency).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ────────────────────────── Top-level Config ──────────────────────────

/// Complete AITP node configuration — mirrors the TOML schema exactly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AitpConfig {
    /// Node identity and networking.
    #[serde(default)]
    pub node: NodeSection,

    /// Control plane registration.
    #[serde(default)]
    pub control_plane: ControlPlaneSection,

    /// UDP transport tuning.
    #[serde(default)]
    pub transport: TransportSection,

    /// Trust engine.
    #[serde(default)]
    pub trust: TrustSection,

    /// AI engine (trust scoring backend).
    #[serde(default)]
    pub ai_engine: AiEngineSection,

    /// Observability.
    #[serde(default)]
    pub observability: ObservabilitySection,

    /// eBPF kernel enforcement.
    #[serde(default)]
    pub ebpf: EbpfSection,
}

/// `[node]` — Identity, networking, and logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSection {
    #[serde(default = "d_node_name")]
    pub name: String,

    #[serde(default = "d_entity_type")]
    pub entity_type: String,

    #[serde(default = "d_key_path")]
    pub identity_key_path: PathBuf,

    #[serde(default = "d_listen_addr")]
    pub listen_address: String,

    #[serde(default = "d_listen_port")]
    pub listen_port: u16,

    #[serde(default = "d_log_level")]
    pub log_level: String,

    #[serde(default = "d_log_format")]
    pub log_format: String,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            name: d_node_name(),
            entity_type: d_entity_type(),
            identity_key_path: d_key_path(),
            listen_address: d_listen_addr(),
            listen_port: d_listen_port(),
            log_level: d_log_level(),
            log_format: d_log_format(),
        }
    }
}

/// `[control_plane]` — Registration and heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneSection {
    #[serde(default = "d_cp_address")]
    pub address: String,

    #[serde(default = "d_heartbeat")]
    pub heartbeat_interval_secs: u64,

    #[serde(default = "d_reg_timeout")]
    pub registration_timeout_secs: u64,
}

impl Default for ControlPlaneSection {
    fn default() -> Self {
        Self {
            address: d_cp_address(),
            heartbeat_interval_secs: d_heartbeat(),
            registration_timeout_secs: d_reg_timeout(),
        }
    }
}

/// `[transport]` — UDP transport tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportSection {
    #[serde(default = "d_max_sessions")]
    pub max_concurrent_sessions: usize,

    #[serde(default = "d_hs_timeout")]
    pub handshake_timeout_secs: u64,

    #[serde(default = "d_hs_retries")]
    pub handshake_max_retries: u32,

    #[serde(default = "d_idle_timeout")]
    pub session_idle_timeout_secs: u64,

    #[serde(default = "d_max_packet")]
    pub max_packet_size_bytes: usize,

    #[serde(default = "d_cwnd_init")]
    pub congestion_window_initial: u32,

    #[serde(default = "d_rtt_probe")]
    pub rtt_probe_interval_ms: u64,
}

impl Default for TransportSection {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: d_max_sessions(),
            handshake_timeout_secs: d_hs_timeout(),
            handshake_max_retries: d_hs_retries(),
            session_idle_timeout_secs: d_idle_timeout(),
            max_packet_size_bytes: d_max_packet(),
            congestion_window_initial: d_cwnd_init(),
            rtt_probe_interval_ms: d_rtt_probe(),
        }
    }
}

/// `[trust]` — Trust engine policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSection {
    #[serde(default = "d_default_policy")]
    pub default_policy: String,

    #[serde(default = "d_eval_timeout")]
    pub trust_eval_timeout_ms: u64,

    #[serde(default = "d_fallback")]
    pub fallback_on_timeout: String,

    #[serde(default = "d_min_allow")]
    pub min_trust_score_allow: u8,

    #[serde(default = "d_min_monitor")]
    pub min_trust_score_monitor: u8,
}

impl Default for TrustSection {
    fn default() -> Self {
        Self {
            default_policy: d_default_policy(),
            trust_eval_timeout_ms: d_eval_timeout(),
            fallback_on_timeout: d_fallback(),
            min_trust_score_allow: d_min_allow(),
            min_trust_score_monitor: d_min_monitor(),
        }
    }
}

/// `[ai_engine]` — Trust scoring backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEngineSection {
    #[serde(default = "d_provider", alias = "mode")]
    pub provider: String,

    #[serde(default = "d_trust_mode")]
    pub trust_mode: String,

    #[serde(default)]
    pub gemini_api_key: String,

    #[serde(default = "d_gemini_model")]
    pub gemini_model: String,

    #[serde(default = "d_gemini_timeout")]
    pub gemini_timeout_ms: u64,

    #[serde(default = "d_gemini_cache")]
    pub gemini_cache_ttl_secs: u64,

    #[serde(default = "d_gemini_rps")]
    pub gemini_max_rps: u32,

    #[serde(default = "d_rules_weight")]
    pub rules_weight: f64,

    #[serde(default = "d_gemini_weight")]
    pub gemini_weight: f64,

    #[serde(default)]
    pub claude_api_key: String,

    #[serde(default = "d_claude_model")]
    pub claude_model: String,

    #[serde(default)]
    pub openai_api_key: String,

    #[serde(default = "d_openai_model")]
    pub openai_model: String,

    #[serde(default = "d_ollama_base_url")]
    pub ollama_base_url: String,

    #[serde(default = "d_ollama_model")]
    pub ollama_model: String,
}

impl Default for AiEngineSection {
    fn default() -> Self {
        Self {
            provider: d_provider(),
            trust_mode: d_trust_mode(),
            gemini_api_key: String::new(),
            gemini_model: d_gemini_model(),
            gemini_timeout_ms: d_gemini_timeout(),
            gemini_cache_ttl_secs: d_gemini_cache(),
            gemini_max_rps: d_gemini_rps(),
            rules_weight: d_rules_weight(),
            gemini_weight: d_gemini_weight(),
            claude_api_key: String::new(),
            claude_model: d_claude_model(),
            openai_api_key: String::new(),
            openai_model: d_openai_model(),
            ollama_base_url: d_ollama_base_url(),
            ollama_model: d_ollama_model(),
        }
    }
}

/// `[observability]` — Metrics and logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilitySection {
    #[serde(default = "d_prom_port")]
    pub prometheus_port: u16,

    #[serde(default)]
    pub otlp_endpoint: String,

    #[serde(default = "d_session_log")]
    pub session_log_path: String,

    #[serde(default = "d_metrics_interval")]
    pub metrics_interval_secs: u64,
}

impl Default for ObservabilitySection {
    fn default() -> Self {
        Self {
            prometheus_port: d_prom_port(),
            otlp_endpoint: String::new(),
            session_log_path: d_session_log(),
            metrics_interval_secs: d_metrics_interval(),
        }
    }
}

/// `[ebpf]` — Kernel enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfSection {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "d_xdp_iface")]
    pub xdp_interface: String,

    #[serde(default = "d_permit_cap")]
    pub permit_map_capacity: usize,
}

impl Default for EbpfSection {
    fn default() -> Self {
        Self {
            enabled: false,
            xdp_interface: d_xdp_iface(),
            permit_map_capacity: d_permit_cap(),
        }
    }
}

// ────────────────────────── Loading ──────────────────────────

impl AitpConfig {
    /// Load configuration with environment variable overrides.
    ///
    /// Priority: env vars > TOML file > built-in defaults.
    ///
    /// # Arguments
    ///
    /// * `path` — Path to a TOML file, or `None` to use defaults only.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read or parsed.
    pub fn load(path: Option<&str>) -> Result<Self, ConfigError> {
        let mut config = match path {
            Some(p) => {
                let pb = PathBuf::from(p);
                if pb.exists() {
                    let contents = std::fs::read_to_string(&pb)
                        .map_err(|e| ConfigError::IoError(pb.clone(), e.to_string()))?;
                    toml::from_str(&contents)
                        .map_err(|e| ConfigError::ParseError(pb, e.to_string()))?
                } else {
                    Self::default()
                }
            }
            None => Self::default(),
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        Ok(config)
    }

    /// Load from a specific file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(path.to_path_buf(), e.to_string()))?;
        let mut config: Self = toml::from_str(&contents)
            .map_err(|e| ConfigError::ParseError(path.to_path_buf(), e.to_string()))?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Serialize to a TOML string for writing templates.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::SerializeError(e.to_string()))
    }

    /// Apply environment variable overrides (AITP_ prefix).
    ///
    /// Each env var maps to a config field via `AITP_SECTION_FIELD` naming.
    fn apply_env_overrides(&mut self) {
        // [node]
        env_override_str("AITP_NODE_NAME", &mut self.node.name);
        env_override_str("AITP_NODE_ENTITY_TYPE", &mut self.node.entity_type);
        env_override_path(
            "AITP_NODE_IDENTITY_KEY_PATH",
            &mut self.node.identity_key_path,
        );
        env_override_str("AITP_NODE_LISTEN_ADDRESS", &mut self.node.listen_address);
        env_override_u16("AITP_NODE_LISTEN_PORT", &mut self.node.listen_port);
        env_override_str("AITP_NODE_LOG_LEVEL", &mut self.node.log_level);
        env_override_str("AITP_NODE_LOG_FORMAT", &mut self.node.log_format);

        // Also support shorthand aliases
        env_override_str("AITP_LOG_LEVEL", &mut self.node.log_level);

        // [control_plane]
        env_override_str(
            "AITP_CONTROL_PLANE_ADDRESS",
            &mut self.control_plane.address,
        );
        env_override_u64(
            "AITP_CONTROL_PLANE_HEARTBEAT_INTERVAL_SECS",
            &mut self.control_plane.heartbeat_interval_secs,
        );
        env_override_u64(
            "AITP_CONTROL_PLANE_REGISTRATION_TIMEOUT_SECS",
            &mut self.control_plane.registration_timeout_secs,
        );

        // [transport]
        env_override_usize(
            "AITP_TRANSPORT_MAX_CONCURRENT_SESSIONS",
            &mut self.transport.max_concurrent_sessions,
        );
        env_override_u64(
            "AITP_TRANSPORT_HANDSHAKE_TIMEOUT_SECS",
            &mut self.transport.handshake_timeout_secs,
        );
        env_override_u32(
            "AITP_TRANSPORT_HANDSHAKE_MAX_RETRIES",
            &mut self.transport.handshake_max_retries,
        );
        env_override_u64(
            "AITP_TRANSPORT_SESSION_IDLE_TIMEOUT_SECS",
            &mut self.transport.session_idle_timeout_secs,
        );
        env_override_usize(
            "AITP_TRANSPORT_MAX_PACKET_SIZE_BYTES",
            &mut self.transport.max_packet_size_bytes,
        );

        // [trust]
        env_override_str("AITP_TRUST_DEFAULT_POLICY", &mut self.trust.default_policy);
        env_override_u64(
            "AITP_TRUST_TRUST_EVAL_TIMEOUT_MS",
            &mut self.trust.trust_eval_timeout_ms,
        );
        env_override_str(
            "AITP_TRUST_FALLBACK_ON_TIMEOUT",
            &mut self.trust.fallback_on_timeout,
        );
        env_override_u8(
            "AITP_TRUST_MIN_TRUST_SCORE_ALLOW",
            &mut self.trust.min_trust_score_allow,
        );
        env_override_u8(
            "AITP_TRUST_MIN_TRUST_SCORE_MONITOR",
            &mut self.trust.min_trust_score_monitor,
        );

        // [ai_engine]
        env_override_str("AITP_AI_ENGINE_PROVIDER", &mut self.ai_engine.provider);
        env_override_str("AITP_AI_ENGINE_TRUST_MODE", &mut self.ai_engine.trust_mode);
        env_override_str(
            "AITP_AI_ENGINE_GEMINI_API_KEY",
            &mut self.ai_engine.gemini_api_key,
        );
        env_override_str(
            "AITP_AI_ENGINE_GEMINI_MODEL",
            &mut self.ai_engine.gemini_model,
        );
        env_override_u64(
            "AITP_AI_ENGINE_GEMINI_TIMEOUT_MS",
            &mut self.ai_engine.gemini_timeout_ms,
        );
        env_override_u64(
            "AITP_AI_ENGINE_GEMINI_CACHE_TTL_SECS",
            &mut self.ai_engine.gemini_cache_ttl_secs,
        );
        env_override_u32(
            "AITP_AI_ENGINE_GEMINI_MAX_RPS",
            &mut self.ai_engine.gemini_max_rps,
        );

        // [observability]
        env_override_u16(
            "AITP_OBSERVABILITY_PROMETHEUS_PORT",
            &mut self.observability.prometheus_port,
        );
        env_override_str(
            "AITP_OBSERVABILITY_OTLP_ENDPOINT",
            &mut self.observability.otlp_endpoint,
        );
        env_override_str(
            "AITP_OBSERVABILITY_SESSION_LOG_PATH",
            &mut self.observability.session_log_path,
        );

        // [ebpf]
        env_override_bool("AITP_EBPF_ENABLED", &mut self.ebpf.enabled);
        env_override_str("AITP_EBPF_XDP_INTERFACE", &mut self.ebpf.xdp_interface);
        env_override_usize(
            "AITP_EBPF_PERMIT_MAP_CAPACITY",
            &mut self.ebpf.permit_map_capacity,
        );
    }

    /// Validate all config values for semantic correctness.
    ///
    /// Returns `Ok(())` if valid, or `Err(Vec<ConfigValidationError>)` with
    /// all detected issues (not just the first one).
    pub fn validate(&self) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // Entity type must be one of the known types
        let valid_entity_types = ["Human", "AiModel", "Service", "Device"];
        if !valid_entity_types.contains(&self.node.entity_type.as_str()) {
            errors.push(ConfigValidationError {
                field: "node.entity_type".into(),
                message: format!(
                    "invalid entity type '{}'. Must be one of: {}",
                    self.node.entity_type,
                    valid_entity_types.join(", ")
                ),
            });
        }

        // Log level must be valid
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.node.log_level.as_str()) {
            errors.push(ConfigValidationError {
                field: "node.log_level".into(),
                message: format!(
                    "invalid log level '{}'. Must be one of: {}",
                    self.node.log_level,
                    valid_levels.join(", ")
                ),
            });
        }

        // Log format must be valid
        let valid_formats = ["json", "pretty"];
        if !valid_formats.contains(&self.node.log_format.as_str()) {
            errors.push(ConfigValidationError {
                field: "node.log_format".into(),
                message: format!(
                    "invalid log format '{}'. Must be one of: {}",
                    self.node.log_format,
                    valid_formats.join(", ")
                ),
            });
        }

        // Listen port: warn if privileged (not a hard error, but noted)
        if self.node.listen_port < 1024 && self.node.listen_port != 0 {
            errors.push(ConfigValidationError {
                field: "node.listen_port".into(),
                message: format!(
                    "port {} is privileged (< 1024) — requires root/CAP_NET_BIND_SERVICE",
                    self.node.listen_port
                ),
            });
        }

        // Trust policy must be valid
        let valid_policies = ["allow", "deny", "monitor"];
        if !valid_policies.contains(&self.trust.default_policy.as_str()) {
            errors.push(ConfigValidationError {
                field: "trust.default_policy".into(),
                message: format!(
                    "invalid policy '{}'. Must be one of: {}",
                    self.trust.default_policy,
                    valid_policies.join(", ")
                ),
            });
        }

        // Fallback policy must be valid
        if !valid_policies.contains(&self.trust.fallback_on_timeout.as_str()) {
            errors.push(ConfigValidationError {
                field: "trust.fallback_on_timeout".into(),
                message: format!(
                    "invalid fallback policy '{}'. Must be one of: {}",
                    self.trust.fallback_on_timeout,
                    valid_policies.join(", ")
                ),
            });
        }

        // min_trust_score_allow must be > min_trust_score_monitor
        if self.trust.min_trust_score_allow <= self.trust.min_trust_score_monitor {
            errors.push(ConfigValidationError {
                field: "trust.min_trust_score_allow".into(),
                message: format!(
                    "min_trust_score_allow ({}) must be > min_trust_score_monitor ({})",
                    self.trust.min_trust_score_allow, self.trust.min_trust_score_monitor
                ),
            });
        }

        // AI engine provider must be valid
        let valid_providers = ["rules", "gemini", "claude", "openai", "ollama"];
        if !valid_providers.contains(&self.ai_engine.provider.as_str()) {
            errors.push(ConfigValidationError {
                field: "ai_engine.provider".into(),
                message: format!(
                    "invalid AI engine provider '{}'. Must be one of: {}",
                    self.ai_engine.provider,
                    valid_providers.join(", ")
                ),
            });
        }

        // AI engine trust mode must be valid
        let valid_modes = ["rules", "ai_only", "hybrid", "rules_only"];
        if !valid_modes.contains(&self.ai_engine.trust_mode.as_str()) {
            errors.push(ConfigValidationError {
                field: "ai_engine.trust_mode".into(),
                message: format!(
                    "invalid AI engine trust mode '{}'. Must be one of: {}",
                    self.ai_engine.trust_mode,
                    valid_modes.join(", ")
                ),
            });
        }

        // If provider requires API key, must be set
        if self.ai_engine.provider == "gemini" && self.ai_engine.gemini_api_key.is_empty() {
            errors.push(ConfigValidationError {
                field: "ai_engine.gemini_api_key".into(),
                message: "gemini_api_key is required when ai_engine.provider is 'gemini' (AITP_AI_ENGINE_GEMINI_API_KEY).".into(),
            });
        }
        if self.ai_engine.provider == "claude" && self.ai_engine.claude_api_key.is_empty() {
            errors.push(ConfigValidationError {
                field: "ai_engine.claude_api_key".into(),
                message: "claude_api_key is required when ai_engine.provider is 'claude'.".into(),
            });
        }
        if self.ai_engine.provider == "openai" && self.ai_engine.openai_api_key.is_empty() {
            errors.push(ConfigValidationError {
                field: "ai_engine.openai_api_key".into(),
                message: "openai_api_key is required when ai_engine.provider is 'openai'.".into(),
            });
        }

        // Gemini timeout must leave overhead budget for trust eval
        if self.ai_engine.gemini_timeout_ms >= self.trust.trust_eval_timeout_ms
            && self.ai_engine.provider == "gemini"
        {
            errors.push(ConfigValidationError {
                field: "ai_engine.gemini_timeout_ms".into(),
                message: format!(
                    "gemini_timeout_ms ({}) must be < trust_eval_timeout_ms ({}) \
                     to leave overhead budget.",
                    self.ai_engine.gemini_timeout_ms, self.trust.trust_eval_timeout_ms
                ),
            });
        }

        // In hybrid mode, weights should sum close to 1.0
        if self.ai_engine.trust_mode == "hybrid" {
            let sum = self.ai_engine.rules_weight + self.ai_engine.gemini_weight;
            if (sum - 1.0).abs() > 0.01 {
                errors.push(ConfigValidationError {
                    field: "ai_engine.rules_weight / gemini_weight".into(),
                    message: format!(
                        "in hybrid mode, rules_weight ({}) + gemini_weight ({}) should sum to 1.0 (got {sum:.2})",
                        self.ai_engine.rules_weight, self.ai_engine.gemini_weight
                    ),
                });
            }
        }

        // Max packet size should be reasonable
        if self.transport.max_packet_size_bytes > 65507 {
            errors.push(ConfigValidationError {
                field: "transport.max_packet_size_bytes".into(),
                message: format!(
                    "max_packet_size_bytes ({}) exceeds UDP maximum of 65507",
                    self.transport.max_packet_size_bytes
                ),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Convenience: construct a `SocketAddr` from `listen_address` + `listen_port`.
    pub fn listen_addr(&self) -> Result<std::net::SocketAddr, ConfigError> {
        let addr_str = format!("{}:{}", self.node.listen_address, self.node.listen_port);
        addr_str.parse().map_err(|e| {
            ConfigError::ParseError(
                PathBuf::from("<listen_addr>"),
                format!("invalid listen address '{}': {}", addr_str, e),
            )
        })
    }
}

// ────────────────────────── Errors ──────────────────────────

/// Configuration loading errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    IoError(PathBuf, String),

    #[error("failed to parse config file {0}: {1}")]
    ParseError(PathBuf, String),

    #[error("failed to serialize config: {0}")]
    SerializeError(String),
}

/// A single validation error with field path and human-readable message.
#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    /// Dot-separated field path (e.g. `"ai_engine.gemini_api_key"`).
    pub field: String,
    /// Human-readable explanation of the problem.
    pub message: String,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.field, self.message)
    }
}

// ────────────────────────── Env Override Helpers ──────────────────────────

fn env_override_str(var: &str, target: &mut String) {
    if let Ok(val) = std::env::var(var) {
        *target = val;
    }
}

fn env_override_path(var: &str, target: &mut PathBuf) {
    if let Ok(val) = std::env::var(var) {
        *target = PathBuf::from(val);
    }
}

fn env_override_u8(var: &str, target: &mut u8) {
    if let Ok(val) = std::env::var(var) {
        if let Ok(v) = val.parse() {
            *target = v;
        }
    }
}

fn env_override_u16(var: &str, target: &mut u16) {
    if let Ok(val) = std::env::var(var) {
        if let Ok(v) = val.parse() {
            *target = v;
        }
    }
}

fn env_override_u32(var: &str, target: &mut u32) {
    if let Ok(val) = std::env::var(var) {
        if let Ok(v) = val.parse() {
            *target = v;
        }
    }
}

fn env_override_u64(var: &str, target: &mut u64) {
    if let Ok(val) = std::env::var(var) {
        if let Ok(v) = val.parse() {
            *target = v;
        }
    }
}

fn env_override_usize(var: &str, target: &mut usize) {
    if let Ok(val) = std::env::var(var) {
        if let Ok(v) = val.parse() {
            *target = v;
        }
    }
}

fn env_override_bool(var: &str, target: &mut bool) {
    if let Ok(val) = std::env::var(var) {
        match val.to_lowercase().as_str() {
            "true" | "1" | "yes" => *target = true,
            "false" | "0" | "no" => *target = false,
            _ => {}
        }
    }
}

// ────────────────────────── Default Values ──────────────────────────

fn d_node_name() -> String {
    "aitp-node".into()
}
fn d_entity_type() -> String {
    "Service".into()
}
fn d_key_path() -> PathBuf {
    PathBuf::from("./keys/node.key")
}
fn d_listen_addr() -> String {
    "0.0.0.0".into()
}
fn d_listen_port() -> u16 {
    9999
}
fn d_log_level() -> String {
    "info".into()
}
fn d_log_format() -> String {
    "json".into()
}

fn d_cp_address() -> String {
    "http://localhost:8080".into()
}
fn d_heartbeat() -> u64 {
    30
}
fn d_reg_timeout() -> u64 {
    5
}

fn d_max_sessions() -> usize {
    10000
}
fn d_hs_timeout() -> u64 {
    5
}
fn d_hs_retries() -> u32 {
    3
}
fn d_idle_timeout() -> u64 {
    300
}
fn d_max_packet() -> usize {
    65507
}
fn d_cwnd_init() -> u32 {
    10
}
fn d_rtt_probe() -> u64 {
    500
}

fn d_default_policy() -> String {
    "deny".into()
}
fn d_eval_timeout() -> u64 {
    5
}
fn d_fallback() -> String {
    "monitor".into()
}
fn d_min_allow() -> u8 {
    128
}
fn d_min_monitor() -> u8 {
    64
}

fn d_provider() -> String {
    "rules".into()
}
fn d_trust_mode() -> String {
    "hybrid".into()
}
fn d_gemini_model() -> String {
    "gemini-2.0-flash".into()
}
fn d_claude_model() -> String {
    "claude-haiku-4-5-20251001".into()
}
fn d_openai_model() -> String {
    "gpt-4o-mini".into()
}
fn d_ollama_base_url() -> String {
    "http://localhost:11434".into()
}
fn d_ollama_model() -> String {
    "llama3.2".into()
}
fn d_gemini_timeout() -> u64 {
    4000
}
fn d_gemini_cache() -> u64 {
    60
}
fn d_gemini_rps() -> u32 {
    100
}
fn d_rules_weight() -> f64 {
    0.4
}
fn d_gemini_weight() -> f64 {
    0.6
}

fn d_prom_port() -> u16 {
    9100
}
fn d_session_log() -> String {
    "/var/log/aitp/sessions.jsonl".into()
}
fn d_metrics_interval() -> u64 {
    15
}

fn d_xdp_iface() -> String {
    "eth0".into()
}
fn d_permit_cap() -> usize {
    65536
}

// ────────────────────────── Legacy Compat ──────────────────────────

/// Legacy `NodeConfig` type alias to maintain backwards compatibility
/// with code that imports this type.
pub type NodeConfig = AitpConfig;

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_loads() {
        let config = AitpConfig::default();
        assert_eq!(config.node.name, "aitp-node");
        assert_eq!(config.node.listen_port, 9999);
        assert_eq!(config.trust.default_policy, "deny");
        assert_eq!(config.ai_engine.provider, "rules");
        assert_eq!(config.ai_engine.trust_mode, "hybrid");
    }

    #[test]
    fn test_default_config_validates() {
        let config = AitpConfig::default();
        // Default config with rules mode should be valid (no privileged port issue)
        let mut c = config;
        c.node.listen_port = 9999; // Non-privileged
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_gemini_mode_requires_api_key() {
        let mut config = AitpConfig::default();
        config.ai_engine.provider = "gemini".into();
        config.ai_engine.gemini_api_key = String::new();
        config.ai_engine.gemini_timeout_ms = 4; // Less than trust timeout

        let errors = config.validate().unwrap_err();
        let key_error = errors
            .iter()
            .find(|e| e.field == "ai_engine.gemini_api_key");
        assert!(key_error.is_some(), "should require gemini_api_key");
        assert!(
            key_error
                .unwrap()
                .message
                .contains("AITP_AI_ENGINE_GEMINI_API_KEY"),
            "error should mention the env var name"
        );
    }

    #[test]
    fn test_gemini_timeout_exceeds_trust_timeout() {
        let mut config = AitpConfig::default();
        config.ai_engine.provider = "gemini".into();
        config.ai_engine.gemini_api_key = "test-key".into();
        config.ai_engine.gemini_timeout_ms = 10; // > trust_eval_timeout_ms (5)

        let errors = config.validate().unwrap_err();
        let timeout_err = errors
            .iter()
            .find(|e| e.field == "ai_engine.gemini_timeout_ms");
        assert!(
            timeout_err.is_some(),
            "should detect timeout budget violation"
        );
    }

    #[test]
    fn test_invalid_log_level() {
        let mut config = AitpConfig::default();
        config.node.log_level = "verbose".into();

        let errors = config.validate().unwrap_err();
        let level_err = errors.iter().find(|e| e.field == "node.log_level");
        assert!(level_err.is_some());
        assert!(
            level_err.unwrap().message.contains("trace"),
            "error should list valid enum variants"
        );
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = AitpConfig::default();
        let toml_str = config.to_toml_string().expect("serialize");
        let parsed: AitpConfig = toml::from_str(&toml_str).expect("parse");
        assert_eq!(parsed.node.name, config.node.name);
        assert_eq!(
            parsed.transport.max_concurrent_sessions,
            config.transport.max_concurrent_sessions
        );
        assert_eq!(parsed.trust.default_policy, config.trust.default_policy);
    }

    #[test]
    fn test_template_file_parses() {
        let toml_str = include_str!("../../config/aitp.toml");
        let config: AitpConfig = toml::from_str(toml_str).expect("template must parse");
        assert_eq!(config.node.name, "aitp-node-alpha");
        assert_eq!(config.transport.max_concurrent_sessions, 10000);
    }

    #[test]
    fn test_hybrid_mode_weights_must_sum_to_one() {
        let mut config = AitpConfig::default();
        config.ai_engine.trust_mode = "hybrid".into();
        config.ai_engine.provider = "gemini".into();
        config.ai_engine.gemini_api_key = "key".into();
        config.ai_engine.gemini_timeout_ms = 4;
        config.ai_engine.rules_weight = 0.3;
        config.ai_engine.gemini_weight = 0.3; // sum = 0.6, not 1.0

        let errors = config.validate().unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("sum to 1.0")));
    }

    #[test]
    fn test_max_packet_size_too_large() {
        let mut config = AitpConfig::default();
        config.transport.max_packet_size_bytes = 70000;

        let errors = config.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field == "transport.max_packet_size_bytes"));
    }

    #[test]
    fn test_listen_addr_construction() {
        let config = AitpConfig::default();
        let addr = config.listen_addr().expect("valid addr");
        assert_eq!(addr.port(), 9999);
        assert_eq!(addr.ip().to_string(), "0.0.0.0");
    }
}
