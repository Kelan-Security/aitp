use super::{SessionContext, TrustResult, TrustVerdict};

/// Deterministic rules-based trust engine. Target latency: <0.5ms.
pub struct RulesEngine;

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate trust using deterministic rules.
    pub fn evaluate(&self, ctx: &SessionContext) -> TrustResult {
        let mut score: i32 = 128; // Start at neutral
        let mut flags: Vec<String> = Vec::new();
        let mut risk = "None".to_string();
        let mut reasons: Vec<String> = Vec::new();

        // Rule 1: Unknown entity → score 0, deny always
        if ctx.source_entity_id.is_empty() {
            return TrustResult {
                trust_score: 0,
                verdict: TrustVerdict::Deny,
                primary_risk: "Unknown entity".to_string(),
                reasoning: "Source entity ID is empty — identity required".to_string(),
                confidence: 1.0,
                behavioral_flags: vec!["unknown_entity".to_string()],
                evaluation_ms: 0.0,
                source: "rules".to_string(),
            };
        }

        // Rule 2: New entity (age < 1 hour) → cap score at 100
        if ctx.entity_age_hours < 1.0 {
            score = score.min(100);
            flags.push("new_entity".to_string());
            reasons.push("New entity — trust capped".to_string());
        }

        // Rule 3: ControlSignal intent → subtract 25
        if ctx.intent == "ControlSignal" {
            score -= 25;
            flags.push("control_signal".to_string());
            risk = "ControlSignal intent".to_string();
            reasons.push("ControlSignal intent penalized".to_string());
        }

        // Rule 4: Behavioral anomaly flags → subtract 30 per flag
        for flag in &ctx.behavioral_flags {
            score -= 30;
            flags.push(flag.clone());
        }
        if !ctx.behavioral_flags.is_empty() {
            risk = format!("{} anomaly flag(s)", ctx.behavioral_flags.len());
            reasons.push(format!(
                "{} behavioral anomalies detected",
                ctx.behavioral_flags.len()
            ));
        }

        // Rule 5: Known peer + established → add up to 30
        if ctx.known_peer && ctx.entity_age_hours >= 24.0 {
            score += 30;
            reasons.push("Established peer relationship bonus".to_string());
        } else if ctx.known_peer {
            score += 15;
            reasons.push("Known peer bonus".to_string());
        }

        // Rule 6: Consistent with historical patterns → add 20
        if ctx.avg_trust_score >= 140.0 && ctx.session_count_24h > 5 {
            score += 20;
            reasons.push("High historical trust score".to_string());
        }

        // Rule 7: Excessive session count in 24h → penalize
        if ctx.session_count_24h > 100 {
            score -= 20;
            flags.push("high_session_rate".to_string());
            reasons.push("Excessive session rate".to_string());
        }

        // Rule 8: Off-hours activity (outside 6am-10pm) → light penalty
        if ctx.time_of_day_hour < 6 || ctx.time_of_day_hour > 22 {
            score -= 10;
            flags.push("off_hours".to_string());
            reasons.push("Off-hours activity".to_string());
        }

        // Rule 9: High clearance entity accessing low-clearance resource → monitor
        if ctx.source_clearance >= 2 {
            score += 10; // Higher-clearance entities get inherent trust
        }

        // Clamp to 0-255
        let trust_score = score.clamp(0, 255) as u8;

        // Determine verdict
        let verdict = if trust_score >= 128 {
            TrustVerdict::Allow
        } else if trust_score >= 64 {
            TrustVerdict::Monitor
        } else {
            TrustVerdict::Deny
        };

        if risk == "None" && !reasons.is_empty() {
            risk = reasons[0].clone();
        }

        TrustResult {
            trust_score,
            verdict,
            primary_risk: risk,
            reasoning: if reasons.is_empty() {
                "Standard trust evaluation — no anomalies".to_string()
            } else {
                reasons.join("; ")
            },
            confidence: 0.85,
            behavioral_flags: flags,
            evaluation_ms: 0.0,
            source: "rules".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_ctx() -> SessionContext {
        SessionContext {
            org_id: "test-org".to_string(),
            source_entity_id: "abc123".to_string(),
            source_entity_type: "workstation".to_string(),
            source_department: Some("Engineering".to_string()),
            source_clearance: 0,
            dest_entity_id: "def456".to_string(),
            dest_entity_type: "server".to_string(),
            intent: "ModelInference".to_string(),
            entity_age_hours: 48.0,
            session_count_24h: 10,
            avg_trust_score: 150.0,
            known_peer: true,
            behavioral_flags: vec![],
            time_of_day_hour: 14,
        }
    }

    #[test]
    fn test_normal_session_allowed() {
        let engine = RulesEngine::new();
        let r = engine.evaluate(&base_ctx());
        assert_eq!(r.verdict, TrustVerdict::Allow);
        assert!(r.trust_score >= 128);
    }

    #[test]
    fn test_unknown_entity_denied() {
        let engine = RulesEngine::new();
        let mut ctx = base_ctx();
        ctx.source_entity_id = String::new();
        let r = engine.evaluate(&ctx);
        assert_eq!(r.verdict, TrustVerdict::Deny);
        assert_eq!(r.trust_score, 0);
    }

    #[test]
    fn test_new_entity_capped() {
        let engine = RulesEngine::new();
        let mut ctx = base_ctx();
        ctx.entity_age_hours = 0.5;
        ctx.known_peer = false;
        let r = engine.evaluate(&ctx);
        assert!(r.trust_score <= 120); // capped at 100 + possible small bonuses
    }

    #[test]
    fn test_control_signal_penalty() {
        let engine = RulesEngine::new();
        let mut ctx = base_ctx();
        ctx.intent = "ControlSignal".to_string();
        let r1 = engine.evaluate(&base_ctx());
        let r2 = engine.evaluate(&ctx);
        assert!(r2.trust_score < r1.trust_score);
    }

    #[test]
    fn test_behavioral_flags_penalty() {
        let engine = RulesEngine::new();
        let mut ctx = base_ctx();
        ctx.behavioral_flags = vec!["TrustScoreDrop".into(), "LateralMovement".into()];
        ctx.known_peer = false;
        let r = engine.evaluate(&ctx);
        assert!(r.trust_score < 128); // 128 - 60 behavioral + possible others
    }

    #[test]
    fn test_off_hours_penalty() {
        let engine = RulesEngine::new();
        let mut ctx = base_ctx();
        ctx.time_of_day_hour = 3;
        let r = engine.evaluate(&ctx);
        let r_normal = engine.evaluate(&base_ctx());
        assert!(r.trust_score < r_normal.trust_score);
    }

    #[test]
    fn test_high_session_rate_penalty() {
        let engine = RulesEngine::new();
        let mut ctx = base_ctx();
        ctx.session_count_24h = 200;
        let r = engine.evaluate(&ctx);
        let r_normal = engine.evaluate(&base_ctx());
        assert!(r.trust_score < r_normal.trust_score);
    }
}
