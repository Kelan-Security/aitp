use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::provider::{AiProvider, AiTrustResult};
use crate::providers::claude::ClaudeProvider;
use crate::providers::gemini::GeminiProvider;
use crate::providers::ollama::OllamaProvider;
use crate::providers::openai::OpenAiProvider;
use crate::providers::rules::RulesProvider;
use crate::scorer::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IntentCode {
    Unknown = 0x0000,
    ModelInference = 0x0001,
    DataSync = 0x0002,
    ControlSignal = 0x0003,
    Telemetry = 0x0004,
    AgentCoordinate = 0x0005,
    FileTransfer = 0x0006,
    Heartbeat = 0x00FF,
}

impl IntentCode {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0000 => IntentCode::Unknown,
            0x0001 => IntentCode::ModelInference,
            0x0002 => IntentCode::DataSync,
            0x0003 => IntentCode::ControlSignal,
            0x0004 => IntentCode::Telemetry,
            0x0005 => IntentCode::AgentCoordinate,
            0x0006 => IntentCode::FileTransfer,
            0x00FF => IntentCode::Heartbeat,
            _ => IntentCode::Unknown,
        }
    }
}

pub struct TrustContext {
    pub source_entity_id: [u8; 32],
    pub dest_entity_id: [u8; 32],
    pub intent_code: u16,
    pub identity_age_secs: u64,
    pub session_frequency: u32,
    pub historical_score: Option<f32>,
    pub behavioral_flags: Vec<String>,
    pub time_of_day: u8,
}

impl TrustContext {
    pub fn cache_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.source_entity_id.hash(&mut hasher);
        self.dest_entity_id.hash(&mut hasher);
        self.intent_code.hash(&mut hasher);
        hasher.finish()
    }
}

#[derive(Clone)]
pub struct AiEngineConfig {
    pub provider: String,
    pub trust_mode: String,
    pub gemini_api_key: String,
    pub gemini_model: String,
    pub gemini_timeout_ms: u64,
    pub gemini_cache_ttl_secs: u64,
    pub gemini_max_rps: u32,
    pub rules_weight: f64,
    pub gemini_weight: f64,
    pub claude_api_key: String,
    pub claude_model: String,
    pub openai_api_key: String,
    pub openai_model: String,
    pub ollama_base_url: String,
    pub ollama_model: String,
}

impl Default for AiEngineConfig {
    fn default() -> Self {
        Self {
            provider: "rules".to_string(),
            trust_mode: "fallback".to_string(),
            gemini_api_key: String::new(),
            gemini_model: "gemini-2.5-flash".to_string(),
            gemini_timeout_ms: 5000,
            gemini_cache_ttl_secs: 300,
            gemini_max_rps: 10,
            rules_weight: 1.0,
            gemini_weight: 1.0,
            claude_api_key: String::new(),
            claude_model: "claude-3".to_string(),
            openai_api_key: String::new(),
            openai_model: "gpt-4o".to_string(),
            ollama_base_url: "http://localhost:11434".to_string(),
            ollama_model: "llama3".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionConstraints {
    pub rate_limit_rps: u32,
    pub max_payload_bytes: u32,
    pub allowed_intents: Vec<IntentCode>,
}

impl Default for SessionConstraints {
    fn default() -> Self {
        Self {
            rate_limit_rps: 100,
            max_payload_bytes: 65535,
            allowed_intents: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReasonCode {
    Ok,
    ContextBlocked,
}

impl From<String> for ReasonCode {
    fn from(_: String) -> Self {
        ReasonCode::ContextBlocked
    }
}

pub struct TrustDecision {
    pub verdict: Verdict,
    pub trust_score: u8,
    pub constraints: SessionConstraints,
    pub reason_code: ReasonCode,
    pub eval_time_ns: u64,
}

impl TrustDecision {
    pub fn from_ai_result(res: AiTrustResult, eval_time_ns: u64) -> Self {
        Self {
            verdict: res.verdict,
            trust_score: res.trust_score,
            constraints: SessionConstraints {
                rate_limit_rps: 100,
                max_payload_bytes: 65535,
                allowed_intents: vec![],
            },
            reason_code: ReasonCode::from(res.reasoning),
            eval_time_ns,
        }
    }
}

pub struct TrustMetrics {
    pub evals_total: AtomicU64,
    pub evals_fallback: AtomicU64,
}

impl TrustMetrics {
    pub fn new() -> Self {
        Self {
            evals_total: AtomicU64::new(0),
            evals_fallback: AtomicU64::new(0),
        }
    }
}

pub struct TrustEngine {
    primary: Arc<dyn AiProvider>,
    fallback: Arc<RulesProvider>,
    config: AiEngineConfig,
    metrics: Arc<TrustMetrics>,
}

impl TrustEngine {
    pub fn with_defaults() -> Self {
        Self::new(AiEngineConfig::default()).unwrap()
    }

    pub fn with_gemini(api_key: &str) -> Self {
        let mut config = AiEngineConfig::default();
        config.provider = "gemini".to_string();
        config.gemini_api_key = api_key.to_string();
        Self::new(config).unwrap()
    }

    pub fn new(config: AiEngineConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let fallback = Arc::new(RulesProvider::new());
        let primary: Arc<dyn AiProvider> = match config.provider.as_str() {
            "gemini" => Arc::new(GeminiProvider::new(&config)?),
            "claude" => Arc::new(ClaudeProvider::new(&config)?),
            "openai" => Arc::new(OpenAiProvider::new(&config)?),
            "ollama" => Arc::new(OllamaProvider::new(&config)?),
            "rules" => fallback.clone(),
            _ => fallback.clone(),
        };

        Ok(Self {
            primary,
            fallback,
            config,
            metrics: Arc::new(TrustMetrics::new()),
        })
    }

    pub async fn evaluate(&self, ctx: &TrustContext) -> TrustDecision {
        let start = Instant::now();
        self.metrics.evals_total.fetch_add(1, Ordering::Relaxed);

        if self.config.trust_mode == "rules" || self.config.trust_mode == "rules_only" {
            let res = self.fallback.evaluate_trust(ctx, "").await.unwrap();
            return TrustDecision::from_ai_result(res, start.elapsed().as_nanos() as u64);
        }

        let timeout_duration = Duration::from_millis(self.config.gemini_timeout_ms);
        let system_prompt = "You are AITP Trust Engine. Evaluate this intent.";

        let ai_result = match timeout(
            timeout_duration,
            self.primary.evaluate_trust(ctx, system_prompt),
        )
        .await
        {
            Ok(Ok(res)) => res,
            _ => {
                self.metrics.evals_fallback.fetch_add(1, Ordering::Relaxed);
                self.fallback.evaluate_trust(ctx, "").await.unwrap()
            }
        };

        if self.config.trust_mode == "hybrid" {
            let rules_res = self.fallback.evaluate_trust(ctx, "").await.unwrap();
            let hybrid_score = (ai_result.trust_score as f64 * self.config.gemini_weight
                + rules_res.trust_score as f64 * self.config.rules_weight)
                as u8;

            let mut final_res = ai_result;
            final_res.trust_score = hybrid_score;
            TrustDecision::from_ai_result(final_res, start.elapsed().as_nanos() as u64)
        } else {
            TrustDecision::from_ai_result(ai_result, start.elapsed().as_nanos() as u64)
        }
    }
}
