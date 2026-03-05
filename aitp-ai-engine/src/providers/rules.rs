use crate::engine::{IntentCode, TrustContext};
use crate::provider::{AiProvider, AiProviderError, AiTrustResult};
use crate::scorer::Verdict;
use async_trait::async_trait;

pub struct RulesProvider {
    // In a full implementation, weights would be configurable
    // weights: RuleWeights,
}

impl RulesProvider {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AiProvider for RulesProvider {
    fn name(&self) -> &'static str {
        "rules"
    }

    async fn evaluate_trust(
        &self,
        ctx: &TrustContext,
        _system_prompt: &str,
    ) -> Result<AiTrustResult, AiProviderError> {
        let score = self.compute_score(ctx);
        Ok(AiTrustResult {
            trust_score: score,
            verdict: self.score_to_verdict(score),
            primary_risk_factor: self.primary_risk(ctx),
            reasoning: "deterministic rule engine — no AI call".into(),
            confidence: 0.7,
            eval_latency_ms: 0,
            provider_name: "rules".into(),
            model_name: "deterministic-v1".into(),
            tokens_used: None,
        })
    }
}

impl RulesProvider {
    fn compute_score(&self, ctx: &TrustContext) -> u8 {
        let mut score: f32 = 128.0; // Start at midpoint

        // Identity age (0–20 points)
        let age_hrs = ctx.identity_age_secs / 3600;
        score += match age_hrs {
            0..=1 => -30.0,
            2..=24 => -10.0,
            25..=168 => 0.0,
            _ => 20.0,
        };

        // Intent risk (0–30 points)
        let intent = IntentCode::from_u16(ctx.intent_code);
        score += match intent {
            IntentCode::Heartbeat => 20.0,
            IntentCode::Telemetry => 15.0,
            IntentCode::ModelInference => 10.0,
            IntentCode::DataSync => 5.0,
            IntentCode::FileTransfer => 0.0,
            IntentCode::AgentCoordinate => -10.0,
            IntentCode::ControlSignal => -25.0,
            IntentCode::Unknown => -40.0,
        };

        // Historical score (30 points weight)
        if let Some(hist) = ctx.historical_score {
            score += (hist as f32 - 128.0) * 0.3;
        }

        // Behavioral flags (-20 per flag)
        score -= ctx.behavioral_flags.len() as f32 * 20.0;

        // Session frequency
        if ctx.session_frequency > 100 {
            score -= 20.0;
        } else if ctx.session_frequency > 50 {
            score -= 10.0;
        }

        score.clamp(0.0, 255.0) as u8
    }

    fn score_to_verdict(&self, score: u8) -> Verdict {
        if score >= 128 {
            Verdict::Allow
        } else if score >= 64 {
            Verdict::Monitor
        } else {
            Verdict::Deny
        }
    }

    fn primary_risk(&self, ctx: &TrustContext) -> String {
        if ctx
            .behavioral_flags
            .iter()
            .any(|f| f.contains("suspicious"))
        {
            "behavior_flags".into()
        } else if ctx.intent_code == 0x0000 {
            "unknown_intent".into()
        } else if ctx.identity_age_secs / 3600 <= 1 {
            "new_identity".into()
        } else {
            "none".into()
        }
    }
}
