//! Integration tests for the Gemini AI trust engine.
//!
//! Tests marked `#[ignore]` require a real Gemini API key:
//!
//! ```bash
//! AITP_AI_ENGINE_GEMINI_API_KEY=<key> cargo test -p aitp-ai-engine --test gemini_integration_test -- --include-ignored
//! ```

use aitp_ai_engine::engine::{TrustContext, TrustEngine};
use aitp_ai_engine::scorer::Verdict;

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
        historical_score: Some(187.0),
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
            "NewIdentity".to_string(),
            "HighFrequency".to_string(),
            "ProbePattern".to_string(),
        ],
        time_of_day: 3,         // 3 AM — suspicious
        session_frequency: 200, // very high
    }
}

// ────────────────────────── Rules-Only Tests ──────────────────────────

#[tokio::test]
async fn test_rules_mode_legitimate_entity() {
    let engine = TrustEngine::with_defaults();
    let ctx = test_context_legitimate();
    let decision = engine.evaluate(&ctx).await;

    assert_eq!(decision.verdict, Verdict::Allow);
    assert!(decision.trust_score > 128);
}

#[tokio::test]
async fn test_rules_mode_anomalous_entity_penalized() {
    let engine = TrustEngine::with_defaults();

    let legitimate = test_context_legitimate();
    let anomalous = test_context_anomalous();

    let legit_decision = engine.evaluate(&legitimate).await;
    let anon_decision = engine.evaluate(&anomalous).await;

    // Anomalous entity should be significantly penalized vs legitimate
    assert!(
        anon_decision.trust_score < legit_decision.trust_score,
        "anomalous ({}) should score lower than legitimate ({})",
        anon_decision.trust_score,
        legit_decision.trust_score
    );
}

// ────────────────────────── Real Gemini API Tests ──────────────────────────

#[tokio::test]
#[ignore = "requires_gemini_api_key"]
async fn test_gemini_allows_legitimate_model_inference() {
    let api_key = gemini_api_key().expect("AITP_AI_ENGINE_GEMINI_API_KEY must be set");

    let engine = TrustEngine::with_gemini(&api_key);

    let ctx = test_context_legitimate();
    let decision = engine.evaluate(&ctx).await;

    println!("Gemini verdict: {:?}", decision.verdict);
    println!("Gemini score: {}", decision.trust_score);

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

    let engine = TrustEngine::with_gemini(&api_key);

    let ctx = test_context_anomalous();
    let decision = engine.evaluate(&ctx).await;

    println!("Gemini verdict: {:?}", decision.verdict);
    println!("Gemini score: {}", decision.trust_score);

    assert!(
        decision.trust_score < 128,
        "anomalous entity should be denied/monitored, score: {}",
        decision.trust_score
    );
}
