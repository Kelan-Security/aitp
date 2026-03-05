use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Note: Ensure `TrustContext` and `Verdict` are properly exported/imported here.
use crate::engine::TrustContext;
use crate::scorer::Verdict;

/// The universal AI provider interface.
/// Every AI backend implements this exactly.
#[async_trait]
pub trait AiProvider: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn evaluate_trust(
        &self,
        ctx: &TrustContext,
        system_prompt: &str,
    ) -> Result<AiTrustResult, AiProviderError>;

    fn supports_streaming(&self) -> bool {
        false
    }
    fn max_context_tokens(&self) -> usize {
        4096
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTrustResult {
    pub trust_score: u8,             // 0–255
    pub verdict: Verdict,            // Allow | Monitor | Deny
    pub primary_risk_factor: String, // Short description
    pub reasoning: String,           // One sentence max
    pub confidence: f32,             // 0.0–1.0
    pub eval_latency_ms: u64,
    pub provider_name: String,
    pub model_name: String,
    pub tokens_used: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum AiProviderError {
    #[error("API request failed: {0}")]
    ApiError(String),
    #[error("Response parse error: {0}")]
    ParseError(String),
    #[error("Rate limit exceeded — try again in {retry_after_secs}s")]
    RateLimit { retry_after_secs: u64 },
    #[error("Timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("Invalid API key")]
    AuthError,
    #[error("Provider unavailable: {0}")]
    Unavailable(String),
    #[error("Invalid provider configuration: {0}")]
    InvalidConfig(String),
}
