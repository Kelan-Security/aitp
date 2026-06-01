//! Policy rule evaluation for trust decisions.
//!
//! Policies are deterministic hard rules checked before the scoring model.
//! They execute in < 0.1ms and can immediately allow or deny a request
//! without invoking the full scoring pipeline.

use serde::{Deserialize, Serialize};

/// The result of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyResult {
    /// Policy explicitly allows — skip scoring.
    Allow,
    /// Policy explicitly denies — skip scoring.
    Deny,
    /// Policy has no strong opinion — proceed to scoring.
    Neutral,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable name.
    pub name: String,
    /// Rule kind.
    pub kind: PolicyRuleKind,
    /// Whether this rule is enabled.
    pub enabled: bool,
}

/// The kind of policy rule and its parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRuleKind {
    /// Always deny connections from identities younger than `min_age_secs`.
    MinIdentityAge { min_age_secs: u64 },
    /// Always deny specific intent codes.
    DenyIntent { intent_code: u16 },
    /// Always allow specific entity IDs (allowlist).
    AllowEntity { entity_id: [u8; 32] },
    /// Always deny specific entity IDs (blocklist).
    DenyEntity { entity_id: [u8; 32] },
    /// Deny if session frequency exceeds threshold in window.
    MaxSessionFrequency { max_per_minute: u32 },
}

/// A set of policy rules evaluated in order.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    rules: Vec<PolicyRule>,
}

impl PolicySet {
    /// Create an empty policy set.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the policy set.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Evaluate all policies against the given context.
    ///
    /// Returns `Allow` or `Deny` on the first matching hard rule.
    /// Returns `Neutral` if no hard rules match.
    ///
    /// # Performance
    ///
    /// This function must complete in < 0.1ms. All rules are evaluated
    /// sequentially with short-circuit on first hard match.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            match &rule.kind {
                PolicyRuleKind::MinIdentityAge { min_age_secs } => {
                    if ctx.identity_age_secs < *min_age_secs {
                        tracing::debug!(
                            rule = %rule.name,
                            identity_age = ctx.identity_age_secs,
                            min_age = min_age_secs,
                            "Policy DENY: identity too young"
                        );
                        return PolicyResult::Deny;
                    }
                }
                PolicyRuleKind::DenyIntent { intent_code } => {
                    if ctx.intent_code == *intent_code {
                        tracing::debug!(
                            rule = %rule.name,
                            intent = ctx.intent_code,
                            "Policy DENY: blocked intent"
                        );
                        return PolicyResult::Deny;
                    }
                }
                PolicyRuleKind::AllowEntity { entity_id } => {
                    if ctx.source_entity_id == *entity_id {
                        tracing::debug!(
                            rule = %rule.name,
                            "Policy ALLOW: allowlisted entity"
                        );
                        return PolicyResult::Allow;
                    }
                }
                PolicyRuleKind::DenyEntity { entity_id } => {
                    if ctx.source_entity_id == *entity_id {
                        tracing::debug!(
                            rule = %rule.name,
                            "Policy DENY: blocklisted entity"
                        );
                        return PolicyResult::Deny;
                    }
                }
                PolicyRuleKind::MaxSessionFrequency { max_per_minute } => {
                    if ctx.session_frequency > *max_per_minute {
                        tracing::debug!(
                            rule = %rule.name,
                            frequency = ctx.session_frequency,
                            max = max_per_minute,
                            "Policy DENY: session frequency exceeded"
                        );
                        return PolicyResult::Deny;
                    }
                }
            }
        }
        PolicyResult::Neutral
    }
}

/// Lightweight context passed to policy evaluation.
///
/// Kept minimal to ensure < 0.1ms evaluation time.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub source_entity_id: [u8; 32],
    pub intent_code: u16,
    pub identity_age_secs: u64,
    pub session_frequency: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_policy_returns_neutral() {
        let policy = PolicySet::new();
        let ctx = PolicyContext {
            source_entity_id: [0u8; 32],
            intent_code: 0x0001,
            identity_age_secs: 3600,
            session_frequency: 1,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Neutral);
    }

    #[test]
    fn test_min_identity_age_deny() {
        let mut policy = PolicySet::new();
        policy.add_rule(PolicyRule {
            name: "min-age".into(),
            kind: PolicyRuleKind::MinIdentityAge { min_age_secs: 3600 },
            enabled: true,
        });
        let ctx = PolicyContext {
            source_entity_id: [0u8; 32],
            intent_code: 0x0001,
            identity_age_secs: 60, // Too young
            session_frequency: 1,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Deny);
    }

    #[test]
    fn test_deny_intent() {
        let mut policy = PolicySet::new();
        policy.add_rule(PolicyRule {
            name: "block-file-transfer".into(),
            kind: PolicyRuleKind::DenyIntent {
                intent_code: 0x0006,
            },
            enabled: true,
        });
        let ctx = PolicyContext {
            source_entity_id: [0u8; 32],
            intent_code: 0x0006,
            identity_age_secs: 3600,
            session_frequency: 1,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Deny);
    }

    #[test]
    fn test_allow_entity() {
        let mut policy = PolicySet::new();
        let allowed_id = [42u8; 32];
        policy.add_rule(PolicyRule {
            name: "allowlist".into(),
            kind: PolicyRuleKind::AllowEntity {
                entity_id: allowed_id,
            },
            enabled: true,
        });
        let ctx = PolicyContext {
            source_entity_id: allowed_id,
            intent_code: 0x0001,
            identity_age_secs: 10,
            session_frequency: 100,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Allow);
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let mut policy = PolicySet::new();
        policy.add_rule(PolicyRule {
            name: "disabled-deny".into(),
            kind: PolicyRuleKind::DenyIntent {
                intent_code: 0x0001,
            },
            enabled: false,
        });
        let ctx = PolicyContext {
            source_entity_id: [0u8; 32],
            intent_code: 0x0001,
            identity_age_secs: 3600,
            session_frequency: 1,
        };
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Neutral);
    }
}
