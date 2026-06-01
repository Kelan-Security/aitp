use async_trait::async_trait;

use std::time::{Duration, Instant};

use crate::engine::{AiEngineConfig, IntentCode, TrustContext};
use crate::provider::{AiProvider, AiProviderError, AiTrustResult};
use crate::scorer::Verdict;

#[derive(Clone)]
pub struct OllamaConfig {
    pub base_url: String,
    pub model: String,
    pub timeout_ms: u64, // Added timeout_ms
}

impl From<&AiEngineConfig> for OllamaConfig {
    // Changed AitpConfigAiEngine to AiEngineConfig
    fn from(c: &AiEngineConfig) -> Self {
        Self {
            base_url: std::env::var("AITP_OLLAMA_BASE_URL")
                .unwrap_or_else(|_| c.ollama_base_url.clone()),
            model: std::env::var("AITP_OLLAMA_MODEL").unwrap_or_else(|_| c.ollama_model.clone()),
            timeout_ms: c.ollama_timeout_ms,
        }
    }
}

pub struct OllamaProvider {
    config: OllamaConfig, // Replaced base_url and model with config
    client: reqwest::Client,
}

impl OllamaProvider {
    pub fn new(config: &AiEngineConfig) -> Result<Self, AiProviderError> {
        // Changed config type and error type
        let ollama_config = OllamaConfig::from(config);

        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(ollama_config.timeout_ms))
                .build()
                .map_err(|e| AiProviderError::InvalidConfig(e.to_string()))?,
            config: ollama_config.clone(),
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
impl AiProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn evaluate_trust(
        &self,
        ctx: &TrustContext,
        system_prompt: &str,
    ) -> Result<AiTrustResult, AiProviderError> {
        let url = format!("{}/api/generate", self.config.base_url); // Used self.config.base_url
        let prompt = format!(
            "{}\n\nUser: {}",
            system_prompt,
            self.build_user_message(ctx)
        );
        let payload = serde_json::json!({
            "model": self.config.model, // Used self.config.model
            "prompt": prompt,
            "format": "json",
            "stream": false,
        });

        let t0 = Instant::now();
        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AiProviderError::ApiError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AiProviderError::ApiError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AiProviderError::ParseError(e.to_string()))?;

        let text = body["response"].as_str().unwrap_or("{}");
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
            provider_name: "ollama".to_string(),
            model_name: self.config.model.clone(),
            tokens_used: body["eval_count"].as_u64().map(|n| n as u32),
        };

        Ok(result)
    }
}
