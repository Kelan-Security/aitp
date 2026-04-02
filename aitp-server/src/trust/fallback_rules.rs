// trust/fallback_rules.rs

use crate::protocol::IntentCode;
use crate::trust::{SessionContext, TrustResult, TrustVerdict};

/// Fully synchronous deterministic evaluator taking under 100 microseconds.
/// Falls back safely when generative interfaces disconnect or breach timeout limits.
pub struct FallbackRulesEngine;

impl FallbackRulesEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, ctx: &SessionContext) -> TrustResult {
        crate::metrics::TRUST_VERDICT_SOURCE.with_label_values(&["rules_fallback"]).inc();
        let start = std::time::Instant::now();

        // Rule 1: Unknown IntentCode
        if IntentCode::from_str_loose(&ctx.intent) == IntentCode::Unknown {
            return self.finalize(TrustResult {
                trust_score: 0,
                verdict: TrustVerdict::Deny,
                primary_risk: "Unknown intent requested".to_string(),
                reasoning: "Protocol declared unmapped IntentCode bypassing strict execution policies.".to_string(),
                confidence: 1.0,
                behavioral_flags: vec!["UnknownIntent".to_string()],
                source: "rules_fallback".to_string(),
                evaluation_ms: 0.0,
            }, start);
        }

        // Rule 2: Auth failure count
        let mut auth_failures = 0;
        for flag in &ctx.behavioral_flags {
            if flag.contains("AuthFailure") {
                auth_failures += 1;
            }
        }
        if auth_failures > 3 {
            return self.finalize(TrustResult {
                trust_score: 25,
                verdict: TrustVerdict::Deny,
                primary_risk: "Brute force authentication".to_string(),
                reasoning: "Session triggered excessive repeated authentication errors.".to_string(),
                confidence: 0.9,
                behavioral_flags: vec!["BruteForce".to_string()],
                source: "rules_fallback".to_string(),
                evaluation_ms: 0.0,
            }, start);
        }

        // Rule 3: DDoS marker or extreme session rate
        if ctx.behavioral_flags.contains(&"DDOSTrafficMarker".to_string()) || ctx.session_count_24h > 10_000 {
            return self.finalize(TrustResult {
                trust_score: 0,
                verdict: TrustVerdict::Deny,
                primary_risk: "Extreme traffic flood".to_string(),
                reasoning: "Entity breached hard packet rate limits indicating DDoS or malfunction.".to_string(),
                confidence: 1.0,
                behavioral_flags: vec!["DDoS".to_string()],
                source: "rules_fallback".to_string(),
                evaluation_ms: 0.0,
            }, start);
        }

        // Rule 4: Explicit malicious intent
        if ctx.intent == "DataExfiltration" || ctx.intent == "MaliciousPayload" {
            return self.finalize(TrustResult {
                trust_score: 0,
                verdict: TrustVerdict::Deny,
                primary_risk: "Malicious intent declared".to_string(),
                reasoning: "Intent matches static blacklist.".to_string(),
                confidence: 1.0,
                behavioral_flags: vec!["MaliciousIntent".to_string()],
                source: "rules_fallback".to_string(),
                evaluation_ms: 0.0,
            }, start);
        }

        // Rule 5: Unknown peer with sensitive intent → Deny
        let is_sensitive = ctx.intent == "ControlSignal" || ctx.intent == "ModelInference";
        if !ctx.known_peer && is_sensitive {
            return self.finalize(TrustResult {
                trust_score: 0,
                verdict: TrustVerdict::Deny,
                primary_risk: "Unauthorized sensitive peer".to_string(),
                reasoning: "Untrusted new peer attempted sensitive protocol execution safely blocked.".to_string(),
                confidence: 0.85,
                behavioral_flags: vec!["UnknownSensitivePeer".to_string()],
                source: "rules_fallback".to_string(),
                evaluation_ms: 0.0,
            }, start);
        }

        // Rule 6: Default fallback → Allow with low confidence
        self.finalize(TrustResult {
            trust_score: 153,
            verdict: TrustVerdict::Allow,
            primary_risk: "Degraded environment assessment".to_string(),
            reasoning: "Generative offline. Matched safe bounds fallback allowing generic routine traffic.".to_string(),
            confidence: 0.6,
            behavioral_flags: vec![],
            source: "rules_fallback".to_string(),
            evaluation_ms: 0.0,
        }, start)
    }

    #[inline(always)]
    fn finalize(&self, mut res: TrustResult, start: std::time::Instant) -> TrustResult {
        res.evaluation_ms = start.elapsed().as_micros() as f64 / 1000.0;
        res
    }
}
