//! Trust scoring engine — weighted rule-based model.
//!
//! Computes a trust score (0–255) using four weighted inputs:
//! - Identity age: 20%
//! - Intent risk: 30%
//! - Session history: 30%
//! - Anomaly flags: 20%
//!
//! Score thresholds:
//! - < 64: Deny
//! - 64–128: Monitor
//! - > 128: Allow

use crate::telemetry::BehaviorFlag;
use serde::{Deserialize, Serialize};

/// Verdict produced by the trust engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Trust score > 128 — connection allowed.
    Allow,
    /// Trust score 64–128 — allowed with monitoring.
    Monitor,
    /// Trust score < 64 — connection denied.
    Deny,
}

impl Verdict {
    /// Determine verdict from a raw trust score.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=63 => Verdict::Deny,
            64..=128 => Verdict::Monitor,
            129..=255 => Verdict::Allow,
        }
    }
}

/// Reason code for the trust decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasonCode {
    /// All checks passed normally.
    Normal,
    /// High trust — established entity with clean history.
    HighTrust,
    /// Identity is too new.
    YoungIdentity,
    /// Intent carries high risk.
    HighRiskIntent,
    /// Session history is poor.
    PoorHistory,
    /// Behavioral anomalies detected.
    AnomalyDetected,
    /// Policy hard-deny triggered.
    PolicyDeny,
    /// Policy hard-allow triggered.
    PolicyAllow,
    /// Deterministic fallback due to timeout.
    TimeoutFallback,
    /// Ollama AI assessment (risk factor from model).
    OllamaAssessment,
}

impl ReasonCode {
    /// Parse a reason code from an Ollama `primary_risk_factor` string.
    pub fn from_string(s: &str) -> Self {
        let lower = s.to_lowercase();
        if lower.contains("anomal") || lower.contains("probe") || lower.contains("flag") {
            Self::AnomalyDetected
        } else if lower.contains("young") || lower.contains("new") || lower.contains("age") {
            Self::YoungIdentity
        } else if lower.contains("risk") || lower.contains("control") || lower.contains("intent") {
            Self::HighRiskIntent
        } else if lower.contains("history") || lower.contains("poor") || lower.contains("prior") {
            Self::PoorHistory
        } else if lower.contains("none") || lower.contains("clean") || lower.contains("trusted") {
            Self::HighTrust
        } else if lower.contains("timeout") {
            Self::TimeoutFallback
        } else {
            Self::OllamaAssessment
        }
    }
}

/// Constraints applied to an allowed session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConstraints {
    /// Maximum payload size in bytes per packet.
    pub max_payload_bytes: u32,
    /// Rate limit: max packets per second.
    pub rate_limit_pps: u32,
    /// Allowed intent codes (empty = all allowed).
    pub allowed_intents: Vec<u16>,
    /// Whether to enable enhanced monitoring.
    pub enhanced_monitoring: bool,
}

impl Default for SessionConstraints {
    fn default() -> Self {
        Self {
            max_payload_bytes: 65535,
            rate_limit_pps: 1000,
            allowed_intents: Vec::new(),
            enhanced_monitoring: false,
        }
    }
}

/// Input context for trust scoring.
#[derive(Debug, Clone)]
pub struct ScoringInput {
    /// Identity age in seconds.
    pub identity_age_secs: u64,
    /// Intent code being requested.
    pub intent_code: u16,
    /// Historical trust score (if available from previous sessions).
    pub historical_score: Option<u8>,
    /// Behavioral flags from telemetry.
    pub behavior_flags: Vec<BehaviorFlag>,
    /// Session frequency: sessions opened per minute by this identity.
    pub session_frequency: u32,
}

/// The trust scorer — a deterministic weighted rule engine.
#[derive(Debug, Clone)]
pub struct TrustScorer {
    /// Minimum identity age to receive full age score (seconds).
    pub min_age_for_full_score: u64,
    /// Intent risk map: intent_code → risk weight (0–255).
    /// Higher = riskier = lower trust.
    intent_risk_map: Vec<(u16, u8)>,
}

impl Default for TrustScorer {
    fn default() -> Self {
        Self {
            min_age_for_full_score: 86400, // 24 hours
            intent_risk_map: vec![
                (0x0001, 80),  // ModelInference — moderate risk
                (0x0002, 60),  // DataSync — lower risk
                (0x0003, 100), // ControlSignal — higher risk
                (0x0004, 20),  // Telemetry — low risk
                (0x0005, 90),  // AgentCoordinate — higher risk
                (0x0006, 120), // FileTransfer — high risk
                (0x00FF, 10),  // Heartbeat — minimal risk
            ],
        }
    }
}

impl TrustScorer {
    /// Create a new scorer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the trust score for the given input.
    ///
    /// # Algorithm
    ///
    /// Four components, each scaled to 0–255:
    /// 1. **Identity age** (20%): linear ramp from 0 to `min_age_for_full_score`
    /// 2. **Intent risk** (30%): inverse of risk weight from intent map
    /// 3. **History** (30%): previous trust score, or 128 if none
    /// 4. **Anomaly** (20%): penalty per behavioral flag
    ///
    /// Final score = weighted sum, clamped to 0–255.
    pub fn score(&self, input: &ScoringInput) -> (u8, ReasonCode) {
        // 1. Identity age component (0–255)
        let age_score = if input.identity_age_secs >= self.min_age_for_full_score {
            255u16
        } else {
            ((input.identity_age_secs as f64 / self.min_age_for_full_score as f64) * 255.0) as u16
        };

        // 2. Intent risk component (0–255, inverted: low risk = high score)
        let risk_weight = self
            .intent_risk_map
            .iter()
            .find(|(code, _)| *code == input.intent_code)
            .map(|(_, w)| *w)
            .unwrap_or(128u8); // Unknown intents get moderate risk
        let intent_score = 255u16.saturating_sub(risk_weight as u16);

        // 3. History component (0–255)
        let history_score = input.historical_score.unwrap_or(128) as u16;

        // 4. Anomaly component (0–255, starts at 255, penalties applied)
        let anomaly_penalty: u16 = input
            .behavior_flags
            .iter()
            .map(|flag| match flag {
                BehaviorFlag::Normal => 0u16,
                BehaviorFlag::NewIdentity => 20,
                BehaviorFlag::HighFrequency => 40,
                BehaviorFlag::OversizedPayload => 30,
                BehaviorFlag::IntentDrift => 50,
                BehaviorFlag::GeoShift => 60,
                BehaviorFlag::ProbePattern => 80,
                BehaviorFlag::AuthFailures => 70,
            })
            .sum();
        let anomaly_score = 255u16.saturating_sub(anomaly_penalty);

        // Weighted sum: age(20%) + intent(30%) + history(30%) + anomaly(20%)
        let weighted = (age_score as f64 * 0.20)
            + (intent_score as f64 * 0.30)
            + (history_score as f64 * 0.30)
            + (anomaly_score as f64 * 0.20);

        let final_score = (weighted.round() as u16).min(255) as u8;

        // Determine primary reason
        let reason = if anomaly_score < 128 {
            ReasonCode::AnomalyDetected
        } else if age_score < 64 {
            ReasonCode::YoungIdentity
        } else if intent_score < 64 {
            ReasonCode::HighRiskIntent
        } else if history_score < 64 {
            ReasonCode::PoorHistory
        } else {
            ReasonCode::Normal
        };

        (final_score, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_from_score() {
        assert_eq!(Verdict::from_score(0), Verdict::Deny);
        assert_eq!(Verdict::from_score(63), Verdict::Deny);
        assert_eq!(Verdict::from_score(64), Verdict::Monitor);
        assert_eq!(Verdict::from_score(128), Verdict::Monitor);
        assert_eq!(Verdict::from_score(129), Verdict::Allow);
        assert_eq!(Verdict::from_score(255), Verdict::Allow);
    }

    #[test]
    fn test_high_trust_established_identity() {
        let scorer = TrustScorer::new();
        let input = ScoringInput {
            identity_age_secs: 100_000, // Well established
            intent_code: 0x00FF,        // Heartbeat — minimal risk
            historical_score: Some(200),
            behavior_flags: vec![BehaviorFlag::Normal],
            session_frequency: 1,
        };
        let (score, reason) = scorer.score(&input);
        assert!(score > 128, "Expected Allow, got score {score}");
        assert_eq!(reason, ReasonCode::Normal);
    }

    #[test]
    fn test_low_trust_new_identity_high_risk() {
        let scorer = TrustScorer::new();
        let input = ScoringInput {
            identity_age_secs: 10, // Brand new
            intent_code: 0x0006,   // FileTransfer — high risk
            historical_score: None,
            behavior_flags: vec![BehaviorFlag::NewIdentity, BehaviorFlag::ProbePattern],
            session_frequency: 50,
        };
        let (score, _reason) = scorer.score(&input);
        assert!(score < 128, "Expected Deny/Monitor, got score {score}");
    }

    #[test]
    fn test_moderate_trust_known_identity() {
        let scorer = TrustScorer::new();
        let input = ScoringInput {
            identity_age_secs: 43200, // 12 hours
            intent_code: 0x0001,      // ModelInference — moderate
            historical_score: Some(128),
            behavior_flags: vec![],
            session_frequency: 5,
        };
        let (score, _) = scorer.score(&input);
        // Should be in the Monitor-Allow range
        assert!(score >= 64, "Score too low: {score}");
    }

    #[test]
    fn test_anomaly_flags_reduce_score() {
        let scorer = TrustScorer::new();
        let base_input = ScoringInput {
            identity_age_secs: 100_000,
            intent_code: 0x0004, // Telemetry — low risk
            historical_score: Some(200),
            behavior_flags: vec![],
            session_frequency: 1,
        };
        let (base_score, _) = scorer.score(&base_input);

        let anomaly_input = ScoringInput {
            behavior_flags: vec![BehaviorFlag::ProbePattern, BehaviorFlag::AuthFailures],
            ..base_input
        };
        let (anomaly_score, _) = scorer.score(&anomaly_input);
        assert!(
            anomaly_score < base_score,
            "Anomaly score {anomaly_score} should be less than base {base_score}"
        );
    }
}
