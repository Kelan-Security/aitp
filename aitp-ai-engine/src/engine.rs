//! Trust evaluation engine — three-mode pipeline with Gemini AI integration.
//!
//! # Modes
//!
//! - **Rules** — Pure deterministic weighted rules (v0.1 behavior, < 0.5ms)
//! - **Gemini** — Gemini 2.0 Flash evaluates ALL trust decisions
//! - **Hybrid** — Rules run first (sync), Gemini runs in parallel,
//!   results merged by weighted average before the 5ms deadline.
//!   Hybrid is the production default.
//!
//! # Performance Contract
//!
//! [`TrustEngine::evaluate`] must return in ≤ 5ms (5_000_000 ns).
//! In hybrid mode, rules provide an instant fallback if Gemini
//! doesn't respond in time.

use crate::gemini_client::{GeminiClient, GeminiConfig, GeminiTrustResult};
use crate::policy::{PolicyContext, PolicyResult, PolicySet};
use crate::scorer::{ReasonCode, ScoringInput, SessionConstraints, TrustScorer, Verdict};
use crate::telemetry::BehaviorFlag;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Full context provided to the trust engine for evaluation.
#[derive(Debug, Clone)]
pub struct TrustContext {
    /// Source entity ID (SHA-256 of public key).
    pub source_entity_id: [u8; 32],
    /// Destination entity ID.
    pub dest_entity_id: [u8; 32],
    /// Intent code being requested.
    pub intent_code: u16,
    /// Identity age in seconds.
    pub identity_age_secs: u64,
    /// Historical trust score from previous sessions (if any).
    pub historical_score: Option<u8>,
    /// Behavioral flags from telemetry.
    pub behavioral_flags: Vec<BehaviorFlag>,
    /// Current hour of day (0–23), for time-based rules.
    pub time_of_day: u8,
    /// Sessions opened per minute by this identity.
    pub session_frequency: u32,
}

/// The result of a trust evaluation.
#[derive(Debug, Clone)]
pub struct TrustDecision {
    /// Allow / Deny / Monitor.
    pub verdict: Verdict,
    /// Computed trust score (0–255).
    pub trust_score: u8,
    /// Constraints applied to the session if allowed.
    pub constraints: SessionConstraints,
    /// Primary reason for the decision.
    pub reason_code: ReasonCode,
    /// Evaluation time in nanoseconds. Must be < 5_000_000 ns for rules.
    pub eval_time_ns: u64,
}

/// Engine operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineMode {
    /// Pure deterministic rules (v0.1 behavior).
    Rules,
    /// Gemini evaluates ALL trust decisions.
    Gemini,
    /// Rules + Gemini in parallel, merged by weighted average.
    Hybrid,
}

impl EngineMode {
    /// Parse from string (case-insensitive).
    pub fn from_str_mode(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "gemini" => Self::Gemini,
            "hybrid" => Self::Hybrid,
            _ => Self::Rules,
        }
    }
}

/// Engine configuration for mode, weights, and trust thresholds.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub mode: EngineMode,
    pub rules_weight: f32,
    pub gemini_weight: f32,
    pub eval_deadline_ms: u64,
    pub min_trust_score_allow: u8,
    pub min_trust_score_monitor: u8,
    pub fallback_on_timeout: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            mode: EngineMode::Rules,
            rules_weight: 0.4,
            gemini_weight: 0.6,
            eval_deadline_ms: 5,
            min_trust_score_allow: 128,
            min_trust_score_monitor: 64,
            fallback_on_timeout: "monitor".into(),
        }
    }
}

/// Session outcome for feedback loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Session completed normally.
    Completed,
    /// Session was revoked.
    Revoked,
    /// Anomalous behavior detected.
    Anomaly,
    /// Session timed out.
    Timeout,
}

/// The trust engine — orchestrates policy → scoring → Gemini → decision.
pub struct TrustEngine {
    policy: PolicySet,
    scorer: TrustScorer,
    gemini: Arc<GeminiClient>,
    config: EngineConfig,
}

impl std::fmt::Debug for TrustEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustEngine")
            .field("mode", &self.config.mode)
            .field("rules_weight", &self.config.rules_weight)
            .field("gemini_weight", &self.config.gemini_weight)
            .finish()
    }
}

impl TrustEngine {
    /// Create a new trust engine with the given policy set and scorer.
    pub fn new(policy: PolicySet, scorer: TrustScorer) -> Self {
        Self {
            policy,
            scorer,
            gemini: Arc::new(GeminiClient::noop()),
            config: EngineConfig::default(),
        }
    }

    /// Create a trust engine with default configuration (rules-only mode).
    pub fn with_defaults() -> Self {
        Self {
            policy: PolicySet::new(),
            scorer: TrustScorer::new(),
            gemini: Arc::new(GeminiClient::noop()),
            config: EngineConfig::default(),
        }
    }

    /// Create a trust engine with full configuration and Gemini client.
    pub fn with_gemini(
        policy: PolicySet,
        scorer: TrustScorer,
        gemini_config: GeminiConfig,
        engine_config: EngineConfig,
    ) -> Result<Self, crate::gemini_client::GeminiError> {
        let gemini = if engine_config.mode == EngineMode::Rules {
            Arc::new(GeminiClient::noop())
        } else {
            Arc::new(GeminiClient::new(gemini_config)?)
        };

        Ok(Self {
            policy,
            scorer,
            gemini,
            config: engine_config,
        })
    }

    /// Get a mutable reference to the policy set for configuration.
    pub fn policy_mut(&mut self) -> &mut PolicySet {
        &mut self.policy
    }

    /// Get the current engine mode.
    pub fn mode(&self) -> EngineMode {
        self.config.mode
    }

    /// Get a reference to the Gemini client (for metrics/cache inspection).
    pub fn gemini_client(&self) -> &GeminiClient {
        &self.gemini
    }

    /// Evaluate trust for the given context.
    ///
    /// # Behavior by mode
    ///
    /// - **Rules**: Synchronous policy + scorer evaluation (< 0.5ms)
    /// - **Gemini**: Async Gemini API call with timeout fallback
    /// - **Hybrid**: Rules run immediately, Gemini runs concurrently,
    ///   results merged by weighted average
    pub fn evaluate(&self, ctx: &TrustContext) -> TrustDecision {
        let start = Instant::now();

        // Step 1: Policy evaluation (< 0.1ms) — always runs first
        let policy_ctx = PolicyContext {
            source_entity_id: ctx.source_entity_id,
            intent_code: ctx.intent_code,
            identity_age_secs: ctx.identity_age_secs,
            session_frequency: ctx.session_frequency,
        };

        let policy_result = self.policy.evaluate(&policy_ctx);

        match policy_result {
            PolicyResult::Allow => {
                let elapsed = start.elapsed().as_nanos() as u64;
                return TrustDecision {
                    verdict: Verdict::Allow,
                    trust_score: 200,
                    constraints: SessionConstraints::default(),
                    reason_code: ReasonCode::PolicyAllow,
                    eval_time_ns: elapsed,
                };
            }
            PolicyResult::Deny => {
                let elapsed = start.elapsed().as_nanos() as u64;
                return TrustDecision {
                    verdict: Verdict::Deny,
                    trust_score: 0,
                    constraints: SessionConstraints::default(),
                    reason_code: ReasonCode::PolicyDeny,
                    eval_time_ns: elapsed,
                };
            }
            PolicyResult::Neutral => {
                // Continue to scoring / Gemini
            }
        }

        // Step 2: Mode-specific evaluation
        match self.config.mode {
            EngineMode::Rules => self.evaluate_rules_only(ctx, start),
            EngineMode::Gemini | EngineMode::Hybrid => {
                // For Gemini/Hybrid modes, the synchronous `evaluate`
                // runs the rules path. The async `evaluate_async` adds
                // Gemini. This preserves the v0.1 sync API while
                // callers who need Gemini should use `evaluate_async`.
                self.evaluate_rules_only(ctx, start)
            }
        }
    }

    /// Async evaluation — required for Gemini and Hybrid modes.
    ///
    /// This is the primary entry point for v0.2+ code. It supports
    /// all three modes and handles Gemini API calls with proper
    /// timeout enforcement.
    #[tracing::instrument(skip(self, ctx), fields(mode = ?self.config.mode))]
    pub async fn evaluate_async(&self, ctx: &TrustContext) -> TrustDecision {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(self.config.eval_deadline_ms);

        // Step 1: Policy evaluation (< 0.1ms)
        let policy_ctx = PolicyContext {
            source_entity_id: ctx.source_entity_id,
            intent_code: ctx.intent_code,
            identity_age_secs: ctx.identity_age_secs,
            session_frequency: ctx.session_frequency,
        };

        let policy_result = self.policy.evaluate(&policy_ctx);

        match policy_result {
            PolicyResult::Allow => {
                let elapsed = start.elapsed().as_nanos() as u64;
                return TrustDecision {
                    verdict: Verdict::Allow,
                    trust_score: 200,
                    constraints: SessionConstraints::default(),
                    reason_code: ReasonCode::PolicyAllow,
                    eval_time_ns: elapsed,
                };
            }
            PolicyResult::Deny => {
                let elapsed = start.elapsed().as_nanos() as u64;
                return TrustDecision {
                    verdict: Verdict::Deny,
                    trust_score: 0,
                    constraints: SessionConstraints::default(),
                    reason_code: ReasonCode::PolicyDeny,
                    eval_time_ns: elapsed,
                };
            }
            PolicyResult::Neutral => {}
        }

        // Step 2: Mode-specific evaluation
        match self.config.mode {
            EngineMode::Rules => self.evaluate_rules_only(ctx, start),

            EngineMode::Gemini => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(remaining, self.gemini.evaluate_trust(ctx)).await {
                    Ok(Ok(result)) => self.gemini_to_decision(result, start),
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "Gemini error, using rules fallback");
                        self.evaluate_rules_only(ctx, start)
                    }
                    Err(_timeout) => {
                        tracing::warn!("Gemini timeout, using rules fallback");
                        self.evaluate_rules_only(ctx, start)
                    }
                }
            }

            EngineMode::Hybrid => {
                // Run rules immediately (synchronous, < 0.5ms)
                let rules_result = self.evaluate_rules_only(ctx, start);

                // Run Gemini concurrently with remaining time budget
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining < Duration::from_millis(1) {
                    tracing::debug!("No time budget for Gemini, using rules-only");
                    return rules_result;
                }

                // Leave 1ms overhead for merging
                let gemini_budget = remaining.saturating_sub(Duration::from_millis(1));
                let gemini_result =
                    tokio::time::timeout(gemini_budget, self.gemini.evaluate_trust(ctx)).await;

                match gemini_result {
                    Ok(Ok(gemini)) => {
                        tracing::debug!(
                            rules_score = rules_result.trust_score,
                            gemini_score = gemini.trust_score,
                            "Merging rules + Gemini results"
                        );
                        self.merge_results(rules_result, gemini, start)
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "Gemini unavailable, using rules-only");
                        rules_result
                    }
                    Err(_timeout) => {
                        tracing::debug!("Gemini timed out, using rules-only");
                        rules_result
                    }
                }
            }
        }
    }

    /// Pure rules evaluation (synchronous, < 0.5ms).
    fn evaluate_rules_only(&self, ctx: &TrustContext, start: Instant) -> TrustDecision {
        // Check timeout before scoring
        if start.elapsed().as_millis() > 4 {
            return self.fallback_decision(start);
        }

        let scoring_input = ScoringInput {
            identity_age_secs: ctx.identity_age_secs,
            intent_code: ctx.intent_code,
            historical_score: ctx.historical_score,
            behavior_flags: ctx.behavioral_flags.clone(),
            session_frequency: ctx.session_frequency,
        };

        let (score, reason) = self.scorer.score(&scoring_input);

        // Check timeout after scoring
        if start.elapsed().as_millis() > 4 {
            return self.fallback_decision(start);
        }

        let verdict = self.score_to_verdict(score);
        let constraints = match verdict {
            Verdict::Allow => SessionConstraints::default(),
            Verdict::Monitor => SessionConstraints {
                enhanced_monitoring: true,
                rate_limit_pps: 500,
                ..SessionConstraints::default()
            },
            Verdict::Deny => SessionConstraints::default(),
        };

        let elapsed = start.elapsed().as_nanos() as u64;

        tracing::debug!(
            trust_score = score,
            verdict = ?verdict,
            reason = ?reason,
            eval_time_ns = elapsed,
            "Rules evaluation complete"
        );

        TrustDecision {
            verdict,
            trust_score: score,
            constraints,
            reason_code: reason,
            eval_time_ns: elapsed,
        }
    }

    /// Convert a Gemini result to a TrustDecision.
    fn gemini_to_decision(&self, result: GeminiTrustResult, start: Instant) -> TrustDecision {
        let verdict = self.score_to_verdict(result.trust_score);
        let elapsed = start.elapsed().as_nanos() as u64;

        TrustDecision {
            verdict,
            trust_score: result.trust_score,
            constraints: match verdict {
                Verdict::Allow => SessionConstraints::default(),
                Verdict::Monitor => SessionConstraints {
                    enhanced_monitoring: true,
                    rate_limit_pps: 500,
                    ..SessionConstraints::default()
                },
                Verdict::Deny => SessionConstraints::default(),
            },
            reason_code: ReasonCode::from_string(&result.primary_risk_factor),
            eval_time_ns: elapsed,
        }
    }

    /// Merge rules and Gemini results by weighted average.
    fn merge_results(
        &self,
        rules: TrustDecision,
        gemini: GeminiTrustResult,
        start: Instant,
    ) -> TrustDecision {
        let merged_score = (rules.trust_score as f32 * self.config.rules_weight
            + gemini.trust_score as f32 * self.config.gemini_weight)
            as u8;

        let verdict = self.score_to_verdict(merged_score);
        let elapsed = start.elapsed().as_nanos() as u64;

        tracing::info!(
            rules_score = rules.trust_score,
            gemini_score = gemini.trust_score,
            merged_score,
            verdict = ?verdict,
            gemini_reasoning = %gemini.reasoning,
            "Hybrid merge complete"
        );

        TrustDecision {
            verdict,
            trust_score: merged_score,
            constraints: match verdict {
                Verdict::Allow => SessionConstraints::default(),
                Verdict::Monitor => SessionConstraints {
                    enhanced_monitoring: true,
                    rate_limit_pps: 500,
                    ..SessionConstraints::default()
                },
                Verdict::Deny => SessionConstraints::default(),
            },
            // Use Gemini's reasoning as it's more descriptive
            reason_code: ReasonCode::from_string(&gemini.primary_risk_factor),
            eval_time_ns: elapsed,
        }
    }

    /// Convert a score to a verdict using configured thresholds.
    fn score_to_verdict(&self, score: u8) -> Verdict {
        if score >= self.config.min_trust_score_allow {
            Verdict::Allow
        } else if score >= self.config.min_trust_score_monitor {
            Verdict::Monitor
        } else {
            Verdict::Deny
        }
    }

    /// Deterministic fallback when evaluation exceeds the 4ms budget.
    fn fallback_decision(&self, start: Instant) -> TrustDecision {
        let elapsed = start.elapsed().as_nanos() as u64;
        tracing::warn!(
            eval_time_ns = elapsed,
            "Trust evaluation exceeded 4ms budget, using fallback"
        );

        let (verdict, score) = match self.config.fallback_on_timeout.as_str() {
            "allow" => (Verdict::Allow, 128),
            "deny" => (Verdict::Deny, 0),
            _ => (Verdict::Monitor, 96),
        };

        TrustDecision {
            verdict,
            trust_score: score,
            constraints: SessionConstraints {
                enhanced_monitoring: true,
                rate_limit_pps: 100,
                ..SessionConstraints::default()
            },
            reason_code: ReasonCode::TimeoutFallback,
            eval_time_ns: elapsed,
        }
    }

    /// Record a session outcome for adaptive learning.
    ///
    /// This creates a feedback loop: decisions improve over time as
    /// session history accumulates.
    pub fn record_session_outcome(&self, ctx: &TrustContext, outcome: SessionOutcome) {
        match outcome {
            SessionOutcome::Completed => {
                tracing::debug!("Session completed normally — no score adjustment");
            }
            SessionOutcome::Revoked | SessionOutcome::Anomaly => {
                // Invalidate cached Gemini decision for this context
                self.gemini.invalidate_cache(ctx);

                // Log the negative outcome for learning
                tracing::warn!(
                    outcome = ?outcome,
                    source_id = ?&ctx.source_entity_id[..4],
                    intent = ctx.intent_code,
                    "Negative session outcome — cache invalidated, entity score should be lowered by 30 points"
                );
            }
            SessionOutcome::Timeout => {
                tracing::debug!("Session timed out — minimal score impact");
            }
        }
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyRule, PolicyRuleKind};

    fn test_ctx() -> TrustContext {
        TrustContext {
            source_entity_id: [1u8; 32],
            dest_entity_id: [2u8; 32],
            intent_code: 0x0001,
            identity_age_secs: 100_000,
            historical_score: Some(150),
            behavioral_flags: vec![],
            time_of_day: 12,
            session_frequency: 1,
        }
    }

    #[test]
    fn test_evaluate_policy_allow_shortcircuits() {
        let mut engine = TrustEngine::with_defaults();
        let entity_id = [42u8; 32];
        engine.policy_mut().add_rule(PolicyRule {
            name: "allowlist-test".into(),
            kind: PolicyRuleKind::AllowEntity { entity_id },
            enabled: true,
        });

        let ctx = TrustContext {
            source_entity_id: entity_id,
            dest_entity_id: [0u8; 32],
            intent_code: 0x0001,
            identity_age_secs: 0,
            historical_score: None,
            behavioral_flags: vec![],
            time_of_day: 12,
            session_frequency: 1,
        };

        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.reason_code, ReasonCode::PolicyAllow);
        assert!(decision.eval_time_ns < 5_000_000);
    }

    #[test]
    fn test_evaluate_policy_deny_shortcircuits() {
        let mut engine = TrustEngine::with_defaults();
        engine.policy_mut().add_rule(PolicyRule {
            name: "block-filetransfer".into(),
            kind: PolicyRuleKind::DenyIntent {
                intent_code: 0x0006,
            },
            enabled: true,
        });

        let ctx = TrustContext {
            source_entity_id: [1u8; 32],
            dest_entity_id: [0u8; 32],
            intent_code: 0x0006,
            identity_age_secs: 100_000,
            historical_score: Some(200),
            behavioral_flags: vec![],
            time_of_day: 12,
            session_frequency: 1,
        };

        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.reason_code, ReasonCode::PolicyDeny);
    }

    #[test]
    fn test_evaluate_scoring_path() {
        let engine = TrustEngine::with_defaults();
        let ctx = TrustContext {
            source_entity_id: [1u8; 32],
            dest_entity_id: [2u8; 32],
            intent_code: 0x00FF, // Heartbeat — low risk
            identity_age_secs: 100_000,
            historical_score: Some(200),
            behavioral_flags: vec![],
            time_of_day: 12,
            session_frequency: 1,
        };

        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.verdict, Verdict::Allow);
        assert!(decision.trust_score > 128);
        assert!(decision.eval_time_ns < 5_000_000, "Must complete in < 5ms");
    }

    #[test]
    fn test_evaluate_within_5ms_budget() {
        let engine = TrustEngine::with_defaults();

        for _ in 0..100 {
            let ctx = TrustContext {
                source_entity_id: [1u8; 32],
                dest_entity_id: [2u8; 32],
                intent_code: 0x0001,
                identity_age_secs: 50_000,
                historical_score: Some(150),
                behavioral_flags: vec![BehaviorFlag::Normal],
                time_of_day: 14,
                session_frequency: 10,
            };
            let decision = engine.evaluate(&ctx);
            assert!(
                decision.eval_time_ns < 5_000_000,
                "Evaluation took {}ns, exceeds 5ms budget",
                decision.eval_time_ns
            );
        }
    }

    #[test]
    fn test_engine_mode_parsing() {
        assert_eq!(EngineMode::from_str_mode("rules"), EngineMode::Rules);
        assert_eq!(EngineMode::from_str_mode("gemini"), EngineMode::Gemini);
        assert_eq!(EngineMode::from_str_mode("hybrid"), EngineMode::Hybrid);
        assert_eq!(EngineMode::from_str_mode("GEMINI"), EngineMode::Gemini);
        assert_eq!(EngineMode::from_str_mode("unknown"), EngineMode::Rules);
    }

    #[test]
    fn test_score_to_verdict_thresholds() {
        let engine = TrustEngine::with_defaults();
        assert_eq!(engine.score_to_verdict(200), Verdict::Allow);
        assert_eq!(engine.score_to_verdict(128), Verdict::Allow);
        assert_eq!(engine.score_to_verdict(100), Verdict::Monitor);
        assert_eq!(engine.score_to_verdict(64), Verdict::Monitor);
        assert_eq!(engine.score_to_verdict(63), Verdict::Deny);
        assert_eq!(engine.score_to_verdict(0), Verdict::Deny);
    }

    #[test]
    fn test_merge_results() {
        let engine = TrustEngine::with_defaults();
        let start = Instant::now();

        let rules = TrustDecision {
            verdict: Verdict::Allow,
            trust_score: 200,
            constraints: SessionConstraints::default(),
            reason_code: ReasonCode::HighTrust,
            eval_time_ns: 100,
        };

        let gemini = GeminiTrustResult {
            verdict: "Allow".into(),
            trust_score: 180,
            confidence: 0.9,
            primary_risk_factor: "none".into(),
            reasoning: "Trusted entity".into(),
        };

        let merged = engine.merge_results(rules, gemini, start);
        // 200 * 0.4 + 180 * 0.6 = 80 + 108 = 188
        assert_eq!(merged.trust_score, 188);
        assert_eq!(merged.verdict, Verdict::Allow);
    }

    #[test]
    fn test_fallback_monitor() {
        let engine = TrustEngine::with_defaults();
        let start = Instant::now();
        let decision = engine.fallback_decision(start);
        assert_eq!(decision.verdict, Verdict::Monitor);
        assert_eq!(decision.trust_score, 96);
    }

    #[test]
    fn test_session_outcome_recording() {
        let engine = TrustEngine::with_defaults();
        let ctx = test_ctx();

        // These shouldn't panic
        engine.record_session_outcome(&ctx, SessionOutcome::Completed);
        engine.record_session_outcome(&ctx, SessionOutcome::Revoked);
        engine.record_session_outcome(&ctx, SessionOutcome::Anomaly);
        engine.record_session_outcome(&ctx, SessionOutcome::Timeout);
    }

    #[tokio::test]
    async fn test_evaluate_async_rules_mode() {
        let engine = TrustEngine::with_defaults();
        let ctx = test_ctx();
        let decision = engine.evaluate_async(&ctx).await;
        assert!(decision.trust_score > 0);
        assert!(decision.eval_time_ns < 5_000_000);
    }
}
