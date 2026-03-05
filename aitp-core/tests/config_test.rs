//! Unit tests for the AITP configuration system.
//!Integration tests for the AITP configuration system.
//!
//! Validates TOML loading, environment variable overrides, validation
//! rules, and error messaging quality.

use aitp_core::config::{AitpConfig, ConfigError};
use std::path::Path;

// ────────────────────────── Valid Config ──────────────────────────

#[test]
fn test_valid_default_config_loads_and_validates() {
    let config = AitpConfig::default();
    assert_eq!(config.node.name, "aitp-node");
    assert_eq!(config.node.listen_port, 9999);
    assert_eq!(config.trust.default_policy, "deny");
    assert_eq!(config.ai_engine.provider, "rules");
    assert_eq!(config.ai_engine.trust_mode, "hybrid");
    assert_eq!(config.transport.max_concurrent_sessions, 10000);

    // Default with non-privileged port should validate
    let mut c = config;
    c.node.listen_port = 9999;
    assert!(c.validate().is_ok(), "default config should validate");
}

#[test]
fn test_template_file_loads_and_validates() {
    let template_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../config/aitp.toml");
    assert!(
        Path::new(template_path).exists(),
        "config/aitp.toml template must exist in repo"
    );

    let config = AitpConfig::from_file(Path::new(template_path)).expect("template TOML must parse");

    assert_eq!(config.node.name, "aitp-node-alpha");
    assert_eq!(config.transport.max_concurrent_sessions, 10000);
    assert_eq!(config.trust.default_policy, "deny");
    assert_eq!(config.ai_engine.provider, "rules");
    assert_eq!(config.ai_engine.trust_mode, "hybrid");
    assert_eq!(config.observability.prometheus_port, 9100);

    // Template uses rules mode, so no Gemini key needed
    assert!(config.validate().is_ok(), "template config should validate");
}

// ────────────────────────── Gemini API Key Validation ──────────────────────────

#[test]
fn test_gemini_mode_requires_api_key() {
    let mut config = AitpConfig::default();
    config.ai_engine.provider = "gemini".into();
    config.ai_engine.gemini_api_key = String::new();
    config.ai_engine.gemini_timeout_ms = 4; // < trust timeout

    let errors = config.validate().unwrap_err();
    let key_error = errors
        .iter()
        .find(|e| e.field == "ai_engine.gemini_api_key");

    assert!(
        key_error.is_some(),
        "should detect missing gemini_api_key. Errors: {:?}",
        errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
    );

    let msg = &key_error.unwrap().message;
    assert!(
        msg.contains("AITP_AI_ENGINE_GEMINI_API_KEY"),
        "error should mention the env var to set: {msg}"
    );
    assert!(
        msg.contains("gemini"),
        "error should mention the mode: {msg}"
    );
}

#[test]
fn test_hybrid_mode_requires_api_key() {
    let mut config = AitpConfig::default();
    config.ai_engine.trust_mode = "hybrid".into();
    config.ai_engine.provider = "gemini".into();
    config.ai_engine.gemini_api_key = String::new();
    config.ai_engine.gemini_timeout_ms = 4;

    let errors = config.validate().unwrap_err();
    assert!(
        errors.iter().any(|e| e.field == "ai_engine.gemini_api_key"),
        "hybrid mode should also require gemini_api_key"
    );
}

#[test]
fn test_rules_mode_does_not_require_api_key() {
    let mut config = AitpConfig::default();
    config.ai_engine.trust_mode = "rules".into();
    config.ai_engine.provider = "rules".into();
    config.ai_engine.gemini_api_key = String::new();

    // With non-privileged port, should validate
    assert!(config.validate().is_ok());
}

// ────────────────────────── Timeout Budget ──────────────────────────

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

    let msg = &timeout_err.unwrap().message;
    assert!(
        msg.contains("trust_eval_timeout_ms"),
        "should reference trust timeout: {msg}"
    );
    assert!(
        msg.contains("overhead"),
        "should mention overhead budget: {msg}"
    );
}

#[test]
fn test_gemini_timeout_exactly_equals_trust_timeout() {
    let mut config = AitpConfig::default();
    config.ai_engine.provider = "gemini".into();
    config.ai_engine.gemini_api_key = "test-key".into();
    config.ai_engine.gemini_timeout_ms = 5; // == trust_eval_timeout_ms
    config.trust.trust_eval_timeout_ms = 5;

    let errors = config.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.field == "ai_engine.gemini_timeout_ms"),
        "equal values should also fail — need at least 1ms overhead"
    );
}

// ────────────────────────── Log Level ──────────────────────────

#[test]
fn test_invalid_log_level_lists_valid_variants() {
    let mut config = AitpConfig::default();
    config.node.log_level = "verbose".into();

    let errors = config.validate().unwrap_err();
    let level_err = errors.iter().find(|e| e.field == "node.log_level");

    assert!(level_err.is_some(), "should detect invalid log level");

    let msg = &level_err.unwrap().message;
    // Should list all valid variants
    for variant in &["trace", "debug", "info", "warn", "error"] {
        assert!(
            msg.contains(variant),
            "error should list '{variant}': {msg}"
        );
    }
}

// ────────────────────────── Environment Variable Overrides ──────────────────────────

#[test]
fn test_env_override_node_name() {
    // Set env var, load config, verify override
    std::env::set_var("AITP_NODE_NAME", "env-override-node");
    let config = AitpConfig::load(None).expect("load should succeed");
    assert_eq!(config.node.name, "env-override-node");
    std::env::remove_var("AITP_NODE_NAME");
}

#[test]
fn test_env_override_listen_port() {
    std::env::set_var("AITP_NODE_LISTEN_PORT", "4444");
    let config = AitpConfig::load(None).expect("load should succeed");
    assert_eq!(config.node.listen_port, 4444);
    std::env::remove_var("AITP_NODE_LISTEN_PORT");
}

#[test]
fn test_env_override_trust_policy() {
    std::env::set_var("AITP_TRUST_DEFAULT_POLICY", "allow");
    let config = AitpConfig::load(None).expect("load should succeed");
    assert_eq!(config.trust.default_policy, "allow");
    std::env::remove_var("AITP_TRUST_DEFAULT_POLICY");
}

#[test]
fn test_env_override_gemini_api_key() {
    std::env::set_var("AITP_AI_ENGINE_GEMINI_API_KEY", "sk-test-key-12345");
    let config = AitpConfig::load(None).expect("load should succeed");
    assert_eq!(config.ai_engine.gemini_api_key, "sk-test-key-12345");
    std::env::remove_var("AITP_AI_ENGINE_GEMINI_API_KEY");
}

#[test]
fn test_env_override_ebpf_enabled() {
    std::env::set_var("AITP_EBPF_ENABLED", "true");
    let config = AitpConfig::load(None).expect("load should succeed");
    assert!(config.ebpf.enabled);
    std::env::remove_var("AITP_EBPF_ENABLED");
}

// ────────────────────────── Hybrid Mode Weights ──────────────────────────

#[test]
fn test_hybrid_weights_must_sum_to_one() {
    let mut config = AitpConfig::default();
    config.ai_engine.trust_mode = "hybrid".into();
    config.ai_engine.provider = "gemini".into();
    config.ai_engine.gemini_api_key = "key".into();
    config.ai_engine.gemini_timeout_ms = 4;
    config.ai_engine.rules_weight = 0.3;
    config.ai_engine.gemini_weight = 0.3; // sum = 0.6

    let errors = config.validate().unwrap_err();
    assert!(
        errors.iter().any(|e| e.message.contains("sum to 1.0")),
        "should detect weight sum != 1.0"
    );
}

// ────────────────────────── Transport Limits ──────────────────────────

#[test]
fn test_max_packet_size_too_large() {
    let mut config = AitpConfig::default();
    config.transport.max_packet_size_bytes = 70000;

    let errors = config.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.field == "transport.max_packet_size_bytes"),
        "should detect oversized max_packet_size"
    );
}

// ────────────────────────── TOML Roundtrip ──────────────────────────

#[test]
fn test_config_toml_roundtrip() {
    let original = AitpConfig::default();
    let toml_str = original.to_toml_string().expect("serialize");
    let parsed: AitpConfig = toml::from_str(&toml_str).expect("parse");

    assert_eq!(parsed.node.name, original.node.name);
    assert_eq!(parsed.node.listen_port, original.node.listen_port);
    assert_eq!(
        parsed.transport.max_concurrent_sessions,
        original.transport.max_concurrent_sessions
    );
    assert_eq!(parsed.trust.default_policy, original.trust.default_policy);
    assert_eq!(parsed.ai_engine.provider, original.ai_engine.provider);
}

// ────────────────────────── Error Path ──────────────────────────

#[test]
fn test_nonexistent_file_returns_defaults() {
    let config = AitpConfig::load(Some("/tmp/nonexistent-aitp-config-46289.toml"))
        .expect("should fall back to defaults");
    assert_eq!(config.node.name, "aitp-node");
}

#[test]
fn test_invalid_toml_returns_parse_error() {
    let tmp_path = "/tmp/aitp-bad-config-test.toml";
    std::fs::write(tmp_path, "this is not [[valid toml").expect("write temp file");

    let result = AitpConfig::load(Some(tmp_path));
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ParseError(_, msg) => {
            assert!(!msg.is_empty(), "parse error should have a message");
        }
        other => panic!("expected ParseError, got: {other:?}"),
    }

    let _ = std::fs::remove_file(tmp_path);
}

// ────────────────────────── Multiple Errors ──────────────────────────

#[test]
fn test_validation_collects_all_errors() {
    let mut config = AitpConfig::default();
    config.node.log_level = "verbose".into();
    config.node.entity_type = "Robot".into();
    config.trust.default_policy = "maybe".into();
    config.ai_engine.trust_mode = "neural".into();

    let errors = config.validate().unwrap_err();

    // Should have at least 4 errors (log_level, entity_type, default_policy, mode)
    assert!(
        errors.len() >= 4,
        "should collect multiple errors, got {}:\n{}",
        errors.len(),
        errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
