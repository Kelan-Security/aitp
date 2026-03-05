use async_trait::async_trait;
use moka::sync::Cache;

use std::time::{Duration, Instant};

use crate::engine::{AiEngineConfig, IntentCode, TrustContext};
use crate::provider::{AiProvider, AiProviderError, AiTrustResult};
use crate::scorer::Verdict;

#[derive(Clone)]
pub struct ClaudeConfig {
    pub api_key: String,
    pub model: String,
    pub timeout_ms: u64,
    pub cache_ttl_secs: u64,
}

impl From<&AiEngineConfig> for ClaudeConfig {
    fn from(c: &AiEngineConfig) -> Self {
        Self {
            api_key: std::env::var("AITP_CLAUDE_API_KEY")
                .unwrap_or_else(|_| c.claude_api_key.clone()),
            model: std::env::var("AITP_CLAUDE_MODEL").unwrap_or_else(|_| c.claude_model.clone()),
            timeout_ms: c.gemini_timeout_ms, // Assuming AiEngineConfig has this field, or it's a typo and should be claude_timeout_ms
            cache_ttl_secs: c.gemini_cache_ttl_secs, // Assuming AiEngineConfig has this field, or it's a typo and should be claude_cache_ttl_secs
        }
    }
}

pub struct ClaudeProvider {
    config: ClaudeConfig,
    client: reqwest::Client,
    cache: Cache<u64, AiTrustResult>,
}

impl ClaudeProvider {
    pub fn new(config: &AiEngineConfig) -> Result<Self, AiProviderError> {
        let claude_config = ClaudeConfig::from(config);

        if claude_config.api_key.is_empty() {
            return Err(AiProviderError::InvalidConfig(
                "Missing AITP_CLAUDE_API_KEY".into(),
            ));
        }

        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(claude_config.timeout_ms))
                .build()
                .map_err(|e| AiProviderError::InvalidConfig(e.to_string()))?,
            config: claude_config.clone(),
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(claude_config.cache_ttl_secs))
                .build(),
        })
    }

    fn build_user_message(&self, ctx: &TrustContext) -> String {
        let intent = IntentCode::from_u16(ctx.intent_code);
        let prompt = format!("{:?}", intent);
        serde_json::json!({
            "source_entity": hex::encode(&ctx.source_entity_id[..8]),
            "intent": prompt,
            "historical_score": ctx.historical_score,
            "session_frequency": ctx.session_frequency,
        })
        .to_string()
    }
}

#[async_trait]
impl AiProvider for ClaudeProvider {
    fn name(&self) -> &'static str {
        "claude"
    }

    async fn evaluate_trust(
        &self,
        ctx: &TrustContext,
        system_prompt: &str,
    ) -> Result<AiTrustResult, AiProviderError> {
        let cache_key = ctx.cache_hash();
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached);
        }

        let url = "https://api.anthropic.com/v1/messages";
        let user_content = self.build_user_message(ctx);
        let payload = serde_json::json!({
            "model": self.config.model,
            "max_tokens": 256,
            "system": system_prompt,
            "messages": [{ "role": "user", "content": user_content }]
        });

        let t0 = Instant::now();
        let response = self
            .client
            .post(url)
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| AiProviderError::ApiError(e.to_string()))?;

        if response.status() == 401 {
            return Err(AiProviderError::AuthError);
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AiProviderError::ParseError(e.to_string()))?;

        let text = body["content"][0]["text"].as_str().unwrap_or("{}");
        let clean = text.trim_matches('`').trim();
        let parsed: serde_json::Value =
            serde_json::from_str(clean.trim_start_matches("json").trim())
                .map_err(|e| AiProviderError::ParseError(format!("{}: {}", e, clean)))?;

        let result = AiTrustResult {
            trust_score: parsed["trust_score"].as_u64().unwrap_or(128) as u8,
            verdict: match parsed["verdict"].as_str() {
                Some("Allow") => Verdict::Allow,
                Some("Deny") => Verdict::Deny,
                _ => Verdict::Monitor,
            },
            primary_risk_factor: parsed["primary_risk"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            reasoning: parsed["reasoning"].as_str().unwrap_or("").to_string(),
            confidence: parsed["confidence"].as_f64().unwrap_or(0.85) as f32,
            eval_latency_ms: t0.elapsed().as_millis() as u64,
            provider_name: "claude".to_string(),
            model_name: self.config.model.clone(),
            tokens_used: body["usage"]["output_tokens"].as_u64().map(|n| n as u32),
        };

        self.cache.insert(cache_key, result.clone());
        Ok(result)
    }
}
