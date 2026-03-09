pub mod gemini;
pub mod rules;

use serde::{Deserialize, Serialize};

// ────────────────────────── Trust Types ──────────────────────────

/// Trust evaluation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustVerdict {
    Allow,
    Monitor,
    Deny,
}

impl TrustVerdict {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "allow" => TrustVerdict::Allow,
            "monitor" => TrustVerdict::Monitor,
            "deny" => TrustVerdict::Deny,
            _ => TrustVerdict::Deny,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TrustVerdict::Allow => "Allow",
            TrustVerdict::Monitor => "Monitor",
            TrustVerdict::Deny => "Deny",
        }
    }
}

impl std::fmt::Display for TrustVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of a trust evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResult {
    pub trust_score: u8,
    pub verdict: TrustVerdict,
    pub primary_risk: String,
    pub reasoning: String,
    pub confidence: f32,
    pub behavioral_flags: Vec<String>,
    pub evaluation_ms: f64,
    pub source: String, // "rules" | "gemini" | "hybrid"
}

/// Context provided to trust engines for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub source_entity_id: String,
    pub source_entity_type: String,
    pub source_department: Option<String>,
    pub source_clearance: u8,
    pub dest_entity_id: String,
    pub dest_entity_type: String,
    pub intent: String,
    pub entity_age_hours: f64,
    pub session_count_24h: u32,
    pub avg_trust_score: f64,
    pub known_peer: bool,
    pub behavioral_flags: Vec<String>,
    pub time_of_day_hour: u8,
}

// ────────────────────────── Hybrid Engine ──────────────────────────

/// Hybrid trust engine combining deterministic rules and AI evaluation.
pub struct HybridTrustEngine {
    pub rules: rules::RulesEngine,
    pub gemini: Option<gemini::GeminiTrustEngine>,
    pub alpha: f64,   // weight for rules vs AI (alpha=rules weight)
    pub mode: String, // "hybrid" | "rules" | "ai_only"
}

impl HybridTrustEngine {
    pub fn new(gemini_api_key: &str, gemini_model: &str, alpha: f64, mode: &str) -> Self {
        let gemini = if !gemini_api_key.is_empty() {
            Some(gemini::GeminiTrustEngine::new(gemini_api_key, gemini_model))
        } else {
            None
        };

        Self {
            rules: rules::RulesEngine::new(),
            gemini,
            alpha,
            mode: mode.to_string(),
        }
    }

    /// Evaluate trust for a session context.
    pub async fn evaluate(&self, ctx: &SessionContext) -> TrustResult {
        let start = std::time::Instant::now();

        match self.mode.as_str() {
            "rules" => {
                let mut result = self.rules.evaluate(ctx);
                result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                result
            }
            "ai_only" => {
                if let Some(ref gemini) = self.gemini {
                    match gemini.evaluate(ctx).await {
                        Ok(mut result) => {
                            result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                            result
                        }
                        Err(_) => {
                            // Fallback to rules on AI failure
                            let mut result = self.rules.evaluate(ctx);
                            result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                            result.source = "rules_fallback".to_string();
                            result
                        }
                    }
                } else {
                    let mut result = self.rules.evaluate(ctx);
                    result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                    result
                }
            }
            _ => {
                // "hybrid" mode — blend rules + AI
                let rules_result = self.rules.evaluate(ctx);

                let ai_result = if let Some(ref gemini) = self.gemini {
                    match gemini.evaluate(ctx).await {
                        Ok(res) => Some(res),
                        Err(e) => {
                            eprintln!("AI Evaluation Error: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                let mut result = if let Some(ai) = ai_result {
                    // Weighted blend of scores
                    let blended_score = (self.alpha * rules_result.trust_score as f64
                        + (1.0 - self.alpha) * ai.trust_score as f64)
                        as u8;

                    let verdict = if blended_score >= 128 {
                        TrustVerdict::Allow
                    } else if blended_score >= 64 {
                        TrustVerdict::Monitor
                    } else {
                        TrustVerdict::Deny
                    };

                    // Merge behavioral flags
                    let mut flags = rules_result.behavioral_flags;
                    for f in ai.behavioral_flags {
                        if !flags.contains(&f) {
                            flags.push(f);
                        }
                    }

                    TrustResult {
                        trust_score: blended_score,
                        verdict,
                        primary_risk: ai.primary_risk,
                        reasoning: format!("{} (AI: {})", rules_result.reasoning, ai.reasoning),
                        confidence: (rules_result.confidence + ai.confidence) / 2.0,
                        behavioral_flags: flags,
                        evaluation_ms: 0.0,
                        source: "hybrid".to_string(),
                    }
                } else {
                    rules_result
                };

                result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                result
            }
        }
    }
}
