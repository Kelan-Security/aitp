pub mod breaker;
pub mod circuit_breaker;
pub mod fallback_rules;
pub mod gemini;
pub mod rules;

use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use breaker::{CircuitBreaker, CircuitState};

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
    pub org_id: String,
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TrustCacheKey {
    pub source_entity_id: String,
    pub dest_entity_id: String,
    pub intent: String,
}

impl From<&SessionContext> for TrustCacheKey {
    fn from(ctx: &SessionContext) -> Self {
        Self {
            source_entity_id: ctx.source_entity_id.clone(),
            dest_entity_id: ctx.dest_entity_id.clone(),
            intent: ctx.intent.clone(),
        }
    }
}

// ────────────────────────── Hybrid Engine ──────────────────────────

/// Hybrid trust engine combining deterministic rules and AI evaluation.
pub struct HybridTrustEngine {
    pub rules: rules::RulesEngine,
    pub gemini: Option<gemini::GeminiTrustEngine>,
    pub alpha: f64,   // weight for rules vs AI (alpha=rules weight)
    pub mode: String, // "hybrid" | "rules" | "ai_only"
    pub cache: Cache<TrustCacheKey, Arc<TrustResult>>,
    pub breaker: CircuitBreaker,
}

impl HybridTrustEngine {
    pub fn new(
        gemini_client: Arc<crate::ai::GeminiClient>,
        gemini_model: &str,
        alpha: f64,
        mode: &str,
    ) -> Self {
        let gemini = Some(gemini::GeminiTrustEngine::new(gemini_client, gemini_model));

        let cache = Cache::builder()
            .max_capacity(50_000)
            .time_to_live(Duration::from_secs(300)) // 5 min TTL
            .time_to_idle(Duration::from_secs(60)) // Evict if unused 1 min
            .build();

        Self {
            rules: rules::RulesEngine::new(),
            gemini,
            alpha,
            mode: mode.to_string(),
            cache,
            breaker: CircuitBreaker::new(20, 30), // 20% error threshold, 30s timeout
        }
    }

    /// Evaluate trust for a session context.
    pub async fn evaluate(&self, ctx: &SessionContext) -> TrustResult {
        let cache_key = TrustCacheKey::from(ctx);

        if let Some(cached) = self.cache.get(&cache_key).await {
            tracing::debug!(entity_id = %ctx.source_entity_id, "Trust cache hit");
            crate::metrics::TRUST_CACHE
                .with_label_values(&["hit"])
                .inc();
            return (*cached).clone();
        }

        crate::metrics::TRUST_CACHE
            .with_label_values(&["miss"])
            .inc();
        let result = self.evaluate_uncached(ctx).await;
        self.cache.insert(cache_key, Arc::new(result.clone())).await;
        result
    }

    async fn evaluate_uncached(&self, ctx: &SessionContext) -> TrustResult {
        let start = std::time::Instant::now();

        // Circuit breaker check
        let is_ai_allowed = self.breaker.state() != CircuitState::Open;

        match self.mode.as_str() {
            "rules" => {
                let mut result = self.rules.evaluate(ctx);
                result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                result
            }
            "ai_only" if is_ai_allowed => {
                let result = if let Some(ref gemini) = self.gemini {
                    match gemini.evaluate(ctx).await {
                        Ok(mut r) => {
                            self.breaker.record_success();
                            r.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                            r
                        }
                        Err(e) => {
                            tracing::warn!("AI Evaluation Error: {}", e);
                            self.breaker.record_error();
                            let mut r = self.rules.evaluate(ctx);
                            r.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                            r.source = "rules_fallback".to_string();
                            r
                        }
                    }
                } else {
                    let mut r = self.rules.evaluate(ctx);
                    r.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                    r
                };
                result
            }
            "hybrid" if is_ai_allowed => {
                let rules_result = self.rules.evaluate(ctx);

                let ai_result = if let Some(ref gemini) = self.gemini {
                    match gemini.evaluate(ctx).await {
                        Ok(res) => {
                            self.breaker.record_success();
                            Some(res)
                        }
                        Err(e) => {
                            tracing::warn!("AI Evaluation Error: {}", e);
                            self.breaker.record_error();
                            None
                        }
                    }
                } else {
                    None
                };

                let mut result = if let Some(ai) = ai_result {
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
                    let mut r = rules_result;
                    r.source = "rules_fallback".to_string();
                    r
                };

                result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                result
            }
            _ => { // Breaker is OPEN or mode matches nothing
                if self.mode != "rules" {
                    tracing::warn!("Circuit Breaker OPEN. Falling back to rules fast-path.");
                }
                let mut result = self.rules.evaluate(ctx);
                result.evaluation_ms = start.elapsed().as_secs_f64() * 1000.0;
                result.source = "rules_fastpath".to_string();
                result
            }
        }
    }
}
