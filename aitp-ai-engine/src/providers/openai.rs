use async_trait::async_trait;
use moka::sync::Cache;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use crate::engine::{AiEngineConfig, IntentCode, TrustContext};
use crate::provider::{AiProvider, AiProviderError, AiTrustResult};
use crate::scorer::Verdict;

#[derive(Clone)]
pub struct OpenAiConfig {
    pub api_key: String,
    pub model: String,
    pub timeout_ms: u64,
    pub cache_ttl_secs: u64,
}

impl From<&AiEngineConfig> for OpenAiConfig {
    fn from(c: &AiEngineConfig) -> Self {
        Self {
            api_key: std::env::var("AITP_OPENAI_API_KEY")
                .unwrap_or_else(|_| c.openai_api_key.clone()),
            model: std::env::var("AITP_OPENAI_MODEL").unwrap_or_else(|_| c.openai_model.clone()),
            timeout_ms: c.gemini_timeout_ms,
            cache_ttl_secs: c.gemini_cache_ttl_secs,
        }
    }
}

pub struct OpenAiProvider {
    config: OpenAiConfig,
    client: reqwest::Client,
    cache: Arc<Cache<u64, AiTrustResult>>,
}

impl OpenAiProvider {
    pub fn new(config: &AiEngineConfig) -> Result<Self, AiProviderError> {
        let openai_config = OpenAiConfig::from(config);

        if openai_config.api_key.is_empty() {
            return Err(AiProviderError::InvalidConfig(
                "Missing AITP_OPENAI_API_KEY".into(),
            ));
        }

        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(openai_config.timeout_ms))
                .build()
                .map_err(|e| AiProviderError::InvalidConfig(e.to_string()))?,
            config: openai_config.clone(),
            cache: Arc::new(
                Cache::builder()
                    .time_to_live(Duration::from_secs(openai_config.cache_ttl_secs))
                    .build(),
            ),
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
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
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

        let payload = serde_json::json!({
            "model": self.config.model,
            "max_tokens": 256,
            "response_format": { "type": "json_object" },
            "messages": [
                { "role": "system", "content": system_prompt },
                { "role": "user",   "content": self.build_user_message(ctx) }
            ]
        });

        let t0 = Instant::now();
        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(&self.config.api_key)
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

        let text = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("{}");
        let parsed: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| AiProviderError::ParseError(format!("{}: {}", e, text)))?;

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
            provider_name: "openai".to_string(),
            model_name: self.config.model.clone(),
            tokens_used: body["usage"]["total_tokens"].as_u64().map(|n| n as u32),
        };

        self.cache.insert(cache_key, result.clone());
        Ok(result)
    }
}
