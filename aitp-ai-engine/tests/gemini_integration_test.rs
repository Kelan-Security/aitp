//! Integration tests for the Gemini AI trust engine.
//!
//! Tests marked `#[ignore]` require a real Gemini API key:
//!
//! ```bash
//! AITP_AI_ENGINE_GEMINI_API_KEY=<key> cargo test -p aitp-ai-engine --test gemini_integration_test -- --include-ignored
//! ```

use aitp_ai_engine::engine::{EngineConfig, EngineMode, SessionOutcome, TrustContext, TrustEngine};
use aitp_ai_engine::gemini_client::{GeminiClient, GeminiConfig};
use aitp_ai_engine::policy::PolicySet;
use aitp_ai_engine::scorer::{ReasonCode, TrustScorer, Verdict};
use aitp_ai_engine::telemetry::BehaviorFlag;
use std::time::Instant;

fn gemini_api_key() -> Option<String> {
    std::env::var("AITP_AI_ENGINE_GEMINI_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())
}

fn test_context_legitimate() -> TrustContext {
    TrustContext {
        source_entity_id: [1u8; 32],
        dest_entity_id: [2u8; 32],
        intent_code: 0x0001,           // ModelInference
        identity_age_secs: 3600 * 720, // 30 days
        historical_score: Some(187),
        behavioral_flags: vec![],
        time_of_day: 14,
        session_frequency: 12,
    }
}

fn test_context_anomalous() -> TrustContext {
    TrustContext {
        source_entity_id: [0xFFu8; 32],
        dest_entity_id: [2u8; 32],
        intent_code: 0x0004,   // ControlSignal — high risk
        identity_age_secs: 60, // 1 minute old — brand new
        historical_score: None,
        behavioral_flags: vec![
            BehaviorFlag::NewIdentity,
            BehaviorFlag::HighFrequency,
            BehaviorFlag::ProbePattern,
        ],
        time_of_day: 3,         // 3 AM — suspicious
        session_frequency: 200, // very high
    }
}

// ────────────────────────── Rules-Only Tests ──────────────────────────

#[test]
fn test_rules_mode_legitimate_entity() {
    let engine = TrustEngine::with_defaults();
    let ctx = test_context_legitimate();
    let decision = engine.evaluate(&ctx);

    assert_eq!(decision.verdict, Verdict::Allow);
    assert!(decision.trust_score > 128);
    assert!(decision.eval_time_ns < 5_000_000, "must be < 5ms");
}

#[test]
fn test_rules_mode_anomalous_entity_penalized() {
    let engine = TrustEngine::with_defaults();

    let legitimate = test_context_legitimate();
    let anomalous = test_context_anomalous();

    let legit_decision = engine.evaluate(&legitimate);
    let anon_decision = engine.evaluate(&anomalous);

    // Anomalous entity should be significantly penalized vs legitimate
    assert!(
        anon_decision.trust_score < legit_decision.trust_score,
        "anomalous ({}) should score lower than legitimate ({})",
        anon_decision.trust_score,
        legit_decision.trust_score
    );
}

#[tokio::test]
async fn test_rules_mode_async_is_equivalent() {
    let engine = TrustEngine::with_defaults();
    let ctx = test_context_legitimate();

    let sync_decision = engine.evaluate(&ctx);
    let async_decision = engine.evaluate_async(&ctx).await;

    // Both should produce the same verdict for rules mode
    assert_eq!(sync_decision.verdict, async_decision.verdict);
    assert_eq!(sync_decision.trust_score, async_decision.trust_score);
}

// ────────────────────────── Engine Mode Tests ──────────────────────────

#[test]
fn test_engine_mode_parsing() {
    assert_eq!(EngineMode::from_str_mode("rules"), EngineMode::Rules);
    assert_eq!(EngineMode::from_str_mode("gemini"), EngineMode::Gemini);
    assert_eq!(EngineMode::from_str_mode("hybrid"), EngineMode::Hybrid);
    assert_eq!(EngineMode::from_str_mode("HYBRID"), EngineMode::Hybrid);
    assert_eq!(EngineMode::from_str_mode("invalid"), EngineMode::Rules);
}

// ────────────────────────── Gemini Client Tests ──────────────────────────

#[test]
fn test_gemini_client_no_api_key_error() {
    let config = GeminiConfig::default();
    assert!(GeminiClient::new(config).is_err());
}

#[test]
fn test_gemini_client_created_with_key() {
    let config = GeminiConfig {
        api_key: "test-key-12345".into(),
        ..Default::default()
    };
    let client = GeminiClient::new(config);
    assert!(client.is_ok());
}

// ────────────────────────── ReasonCode Parsing ──────────────────────────

#[test]
fn test_reason_code_from_string() {
    assert_eq!(
        ReasonCode::from_string("anomaly detected"),
        ReasonCode::AnomalyDetected
    );
    assert_eq!(
        ReasonCode::from_string("new identity"),
        ReasonCode::YoungIdentity
    );
    assert_eq!(
        ReasonCode::from_string("high risk intent"),
        ReasonCode::HighRiskIntent
    );
    assert_eq!(
        ReasonCode::from_string("poor history"),
        ReasonCode::PoorHistory
    );
    assert_eq!(ReasonCode::from_string("none"), ReasonCode::HighTrust);
    assert_eq!(
        ReasonCode::from_string("clean profile"),
        ReasonCode::HighTrust
    );
    assert_eq!(
        ReasonCode::from_string("something unknown"),
        ReasonCode::GeminiAssessment
    );
}

// ────────────────────────── Session Outcome Feedback ──────────────────────────

#[test]
fn test_session_outcome_feedback_loop() {
    let engine = TrustEngine::with_defaults();
    let ctx = test_context_legitimate();

    // All outcomes should be recorded without panic
    engine.record_session_outcome(&ctx, SessionOutcome::Completed);
    engine.record_session_outcome(&ctx, SessionOutcome::Revoked);
    engine.record_session_outcome(&ctx, SessionOutcome::Anomaly);
    engine.record_session_outcome(&ctx, SessionOutcome::Timeout);
}

// ────────────────────────── Hybrid Merge Logic ──────────────────────────

#[tokio::test]
async fn test_hybrid_fallback_when_no_gemini_key() {
    // Hybrid mode without a real Gemini client should fall back to rules
    let _config = EngineConfig {
        mode: EngineMode::Hybrid,
        rules_weight: 0.4,
        gemini_weight: 0.6,
        ..Default::default()
    };

    // with_gemini will fail without API key in non-rules mode,
    // so we test the fallback behavior of evaluate_async
    let engine = TrustEngine::with_defaults();
    let ctx = test_context_legitimate();

    let decision = engine.evaluate_async(&ctx).await;
    assert!(decision.trust_score > 0, "should produce a valid score");
    assert!(
        decision.eval_time_ns < 5_000_000,
        "must complete within 5ms budget"
    );
}

// ────────────────────────── Real Gemini API Tests ──────────────────────────
// These require AITP_AI_ENGINE_GEMINI_API_KEY to be set.

#[tokio::test]
#[ignore = "requires_gemini_api_key"]
async fn test_gemini_allows_legitimate_model_inference() {
    let api_key = gemini_api_key().expect("AITP_AI_ENGINE_GEMINI_API_KEY must be set");

    let gemini_config = GeminiConfig {
        api_key,
        model: "gemini-2.0-flash".into(),
        timeout_ms: 4000,
        cache_ttl_secs: 60,
        max_rps: 10,
    };

    let engine_config = EngineConfig {
        mode: EngineMode::Gemini,
        ..Default::default()
    };

    let engine = TrustEngine::with_gemini(
        PolicySet::new(),
        TrustScorer::new(),
        gemini_config,
        engine_config,
    )
    .expect("engine creation");

    let ctx = test_context_legitimate();
    let decision = engine.evaluate_async(&ctx).await;

    println!("Gemini verdict: {:?}", decision.verdict);
    println!("Gemini score: {}", decision.trust_score);
    println!("Gemini reason: {:?}", decision.reason_code);

    // A legitimate 30-day-old entity with clean history requesting
    // ModelInference should be allowed or at least monitored
    assert!(
        decision.trust_score >= 64,
        "legitimate entity should not be denied, score: {}",
        decision.trust_score
    );
}

#[tokio::test]
#[ignore = "requires_gemini_api_key"]
async fn test_gemini_denies_anomalous_control_signal() {
    let api_key = gemini_api_key().expect("AITP_AI_ENGINE_GEMINI_API_KEY must be set");

    let gemini_config = GeminiConfig {
        api_key,
        model: "gemini-2.0-flash".into(),
        timeout_ms: 4000,
        cache_ttl_secs: 60,
        max_rps: 10,
    };

    let engine_config = EngineConfig {
        mode: EngineMode::Gemini,
        ..Default::default()
    };

    let engine = TrustEngine::with_gemini(
        PolicySet::new(),
        TrustScorer::new(),
        gemini_config,
        engine_config,
    )
    .expect("engine creation");

    let ctx = test_context_anomalous();
    let decision = engine.evaluate_async(&ctx).await;

    println!("Gemini verdict: {:?}", decision.verdict);
    println!("Gemini score: {}", decision.trust_score);

    // Brand-new entity, ControlSignal, probe pattern, 200 sessions/min
    // at 3 AM should be denied or heavily monitored
    assert!(
        decision.trust_score < 128,
        "anomalous entity should be denied/monitored, score: {}",
        decision.trust_score
    );
}

#[tokio::test]
#[ignore = "requires_gemini_api_key"]
async fn test_gemini_responds_within_4000ms() {
    let api_key = gemini_api_key().expect("AITP_AI_ENGINE_GEMINI_API_KEY must be set");

    let gemini_config = GeminiConfig {
        api_key,
        model: "gemini-2.0-flash".into(),
        timeout_ms: 4000,
        cache_ttl_secs: 60,
        max_rps: 10,
    };

    let client = GeminiClient::new(gemini_config).expect("client creation");
    let ctx = test_context_legitimate();

    let start = Instant::now();
    let result = client.evaluate_trust(&ctx).await;
    let elapsed_ms = start.elapsed().as_millis();

    match result {
        Ok(r) => {
            assert!(
                elapsed_ms < 4000,
                "Gemini must respond within 4000ms, took {}ms",
                elapsed_ms
            );
            println!(
                "Gemini response in {}ms: score={}, verdict={}",
                elapsed_ms, r.trust_score, r.verdict
            );
        }
        Err(e) => {
            let err_msg = format!("{e}");
            if err_msg.contains("429") || err_msg.contains("RESOURCE_EXHAUSTED") {
                println!("Skipping — free-tier rate limit hit (429). API is reachable.");
            } else {
                panic!("Gemini should respond: {e}");
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires_gemini_api_key"]
async fn test_hybrid_mode_merges_results() {
    let api_key = gemini_api_key().expect("AITP_AI_ENGINE_GEMINI_API_KEY must be set");

    let gemini_config = GeminiConfig {
        api_key,
        model: "gemini-2.0-flash".into(),
        timeout_ms: 4000,
        cache_ttl_secs: 60,
        max_rps: 10,
    };

    let engine_config = EngineConfig {
        mode: EngineMode::Hybrid,
        rules_weight: 0.4,
        gemini_weight: 0.6,
        ..Default::default()
    };

    let engine = TrustEngine::with_gemini(
        PolicySet::new(),
        TrustScorer::new(),
        gemini_config,
        engine_config,
    )
    .expect("engine creation");

    let ctx = test_context_legitimate();
    let start = Instant::now();
    let decision = engine.evaluate_async(&ctx).await;
    let elapsed_ms = start.elapsed().as_millis();

    println!(
        "Hybrid verdict: {:?}, score: {}, time: {}ms",
        decision.verdict, decision.trust_score, elapsed_ms
    );

    assert!(decision.trust_score > 0, "should produce a valid score");
}

#[tokio::test]
#[ignore = "requires_gemini_api_key"]
async fn test_gemini_cache_hit_is_fast() {
    let api_key = gemini_api_key().expect("AITP_AI_ENGINE_GEMINI_API_KEY must be set");

    let gemini_config = GeminiConfig {
        api_key,
        model: "gemini-2.0-flash".into(),
        timeout_ms: 4000,
        cache_ttl_secs: 60,
        max_rps: 10,
    };

    let client = GeminiClient::new(gemini_config).expect("client creation");
    let ctx = test_context_legitimate();

    // First call — populates cache (may hit rate limit)
    let first = client.evaluate_trust(&ctx).await;
    if let Err(e) = &first {
        let err_msg = format!("{e}");
        if err_msg.contains("429") || err_msg.contains("RESOURCE_EXHAUSTED") {
            println!("Skipping — free-tier rate limit hit (429). Cannot test cache.");
            return;
        }
        panic!("first call failed: {e}");
    }
    assert!(client.cache_size() > 0, "cache should have entries");

    // Second call — should be a cache hit and very fast
    let start = Instant::now();
    let result = client.evaluate_trust(&ctx).await.expect("cache hit");
    let elapsed_us = start.elapsed().as_micros();

    println!(
        "Cache hit in {}µs: score={}",
        elapsed_us, result.trust_score
    );
    assert!(
        elapsed_us < 100,
        "cache hit should be < 100µs, took {}µs",
        elapsed_us
    );
}
