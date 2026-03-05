use async_trait::async_trait;
use governor::{clock::DefaultClock, state::InMemoryState, state::NotKeyed, Quota, RateLimiter};

use std::sync::Arc;
use std::time::{Duration, Instant};
// Assuming moka cache, but let's just use moka if available. Or simply mock it if not.
use crate::engine::{AiEngineConfig, IntentCode, TrustContext};
use crate::provider::{AiProvider, AiProviderError, AiTrustResult};
use crate::scorer::Verdict;

use moka::sync::Cache;
use std::num::NonZeroU32;

#[derive(Clone)]
pub struct GeminiConfig {
    pub api_key: String,
    pub model: String,
    pub timeout_ms: u64,
    pub cache_ttl_secs: u64,
    pub max_rps: u32,
}

impl From<&AiEngineConfig> for GeminiConfig {
    fn from(c: &AiEngineConfig) -> Self {
        Self {
            api_key: std::env::var("AITP_GEMINI_API_KEY")
                .unwrap_or_else(|_| c.gemini_api_key.clone()),
            model: std::env::var("AITP_GEMINI_MODEL").unwrap_or_else(|_| c.gemini_model.clone()),
            timeout_ms: c.gemini_timeout_ms,
            cache_ttl_secs: c.gemini_cache_ttl_secs,
            max_rps: c.gemini_max_rps,
        }
    }
}

pub struct GeminiProvider {
    config: GeminiConfig,
    client: reqwest::Client,
    cache: Arc<Cache<u64, AiTrustResult>>,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl GeminiProvider {
    pub fn new(config: &AiEngineConfig) -> Result<Self, AiProviderError> {
        let gemini_config = GeminiConfig::from(config);

        if gemini_config.api_key.is_empty() {
            return Err(AiProviderError::InvalidConfig(
                "Missing AITP_GEMINI_API_KEY".into(),
            ));
        }
        Ok(Self {
            config: gemini_config.clone(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(gemini_config.timeout_ms))
                .build()
                .map_err(|e| AiProviderError::InvalidConfig(e.to_string()))?,
            cache: Arc::new(
                Cache::builder()
                    .max_capacity(10_000)
                    .time_to_live(Duration::from_secs(gemini_config.cache_ttl_secs))
                    .build(),
            ),
            rate_limiter: Arc::new(RateLimiter::direct(Quota::per_second(
                NonZeroU32::new(gemini_config.max_rps).unwrap_or(NonZeroU32::new(100).unwrap()),
            ))),
        })
    }

    fn build_payload(
        &self,
        ctx: &TrustContext,
        system_prompt: &str,
        intent: IntentCode,
    ) -> serde_json::Value {
        let user_message = serde_json::json!({
            "source": {
                "entity_id": hex::encode(&ctx.source_entity_id[..8]),
                "identity_age_hours": ctx.identity_age_secs / 3600,
            },
            "destination": {
                "entity_id": hex::encode(&ctx.dest_entity_id[..8]),
            },
            "context": {
                "intent": format!("{:?}", intent),
                "time_of_day": ctx.time_of_day,
                "session_frequency": ctx.session_frequency,
                "behavior_flags": ctx.behavioral_flags,
                "historical_score": ctx.historical_score,
            }
        });

        serde_json::json!({
            "system_instruction": { "parts": [{ "text": system_prompt }] },
            "contents": [{ "parts": [{ "text": user_message.to_string() }] }],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 256,
                "responseMimeType": "application/json",
            }
        })
    }
}

#[async_trait]
impl AiProvider for GeminiProvider {
    fn name(&self) -> &'static str {
        "gemini"
    }

    async fn evaluate_trust(
        &self,
        ctx: &TrustContext,
        system_prompt: &str,
    ) -> Result<AiTrustResult, AiProviderError> {
        let cache_key = ctx.cache_hash();
        if let Some(cached) = self.cache.get(&cache_key) {
            tracing::debug!(provider = "gemini", event = "cache_hit");
            return Ok(cached);
        }

        self.rate_limiter.until_ready().await;

        let intent = IntentCode::from_u16(ctx.intent_code);
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.config.model, self.config.api_key
        );
        let payload = self.build_payload(ctx, system_prompt, intent);

        let t0 = Instant::now();
        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    AiProviderError::Timeout {
                        timeout_ms: self.config.timeout_ms,
                    }
                } else {
                    AiProviderError::ApiError(e.to_string())
                }
            })?;

        let status = response.status();
        if status == 401 {
            return Err(AiProviderError::AuthError);
        }
        if status == 429 {
            return Err(AiProviderError::RateLimit {
                retry_after_secs: 60,
            });
        }
        if !status.is_success() {
            return Err(AiProviderError::ApiError(format!("HTTP {}", status)));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AiProviderError::ParseError(e.to_string()))?;

        let text = body["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("{}");

        let parsed: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| AiProviderError::ParseError(format!("{}: {}", e, text)))?;

        let result = AiTrustResult {
            trust_score: parsed["trust_score"].as_u64().unwrap_or(128) as u8,
            verdict: match parsed["verdict"].as_str().unwrap_or("Monitor") {
                "Allow" => Verdict::Allow,
                "Deny" => Verdict::Deny,
                _ => Verdict::Monitor,
            },
            primary_risk_factor: parsed["primary_risk"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            reasoning: parsed["reasoning"].as_str().unwrap_or("").to_string(),
            confidence: parsed["confidence"].as_f64().unwrap_or(0.8) as f32,
            eval_latency_ms: t0.elapsed().as_millis() as u64,
            provider_name: "gemini".to_string(),
            model_name: self.config.model.clone(),
            tokens_used: body["usageMetadata"]["totalTokenCount"]
                .as_u64()
                .map(|n| n as u32),
        };

        self.cache.insert(cache_key, result.clone());
        Ok(result)
    }
}
