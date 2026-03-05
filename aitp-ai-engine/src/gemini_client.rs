//! Gemini 2.0 Flash client for real-time AI trust evaluation.
//!
//! Calls the Gemini API to get structured trust decisions for
//! AI-to-AI connection requests. Includes:
//! - Response caching (DashMap, configurable TTL)
//! - Rate limiting (governor crate, configurable max RPS)
//! - Structured prompt with deterministic JSON output
//! - Timeout enforcement and error classification

use crate::engine::TrustContext;
use crate::scorer::Verdict;
use dashmap::DashMap;
use governor::{Quota, RateLimiter as GovRateLimiter};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ────────────────────────── System Prompt ──────────────────────────

/// The system prompt sent to Gemini for trust evaluation.
pub const GEMINI_SYSTEM_PROMPT: &str = r#"You are an AI security evaluator embedded in the AITP (Adaptive Intent Transport Protocol).
Your job is to evaluate whether an AI-to-AI network connection should be allowed, monitored, or denied.

You will receive a JSON object describing a connection request.
You must respond with ONLY a valid JSON object — no markdown, no explanation, no preamble.

Response format (strict):
{
  "verdict": "Allow" | "Monitor" | "Deny",
  "trust_score": <integer 0-255>,
  "confidence": <float 0.0-1.0>,
  "primary_risk_factor": "<string>",
  "reasoning": "<one sentence max>"
}

Scoring guide:
- 0-63:   Deny  — High risk, unknown identity, anomalous behavior, dangerous intent
- 64-127: Monitor — Uncertain context, new entity, elevated frequency, ambiguous intent
- 128-255: Allow — Known entity, expected intent, clean history, low anomaly score

Trust factors to weigh:
1. entity_type: AIModel connections requesting ControlSignal intent = elevated scrutiny
2. identity_age_hours: < 1 hour = very new, treat as untrusted until history builds
3. session_frequency: > 100/min = rate anomaly flag
4. historical_score: Strong prior signal — weight at 30%
5. intent: ModelInference = normal, ControlSignal = elevated risk, unknown = deny
6. behavioral_flags: Any flag present = reduce score by 20 points minimum

Be decisive. Latency budget is 5ms total. Do not hedge."#;

// ────────────────────────── Types ──────────────────────────

/// Gemini trust evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiTrustResult {
    /// Allow / Monitor / Deny.
    pub verdict: String,
    /// Trust score 0–255.
    pub trust_score: u8,
    /// Model confidence 0.0–1.0.
    pub confidence: f64,
    /// Primary risk factor identified.
    pub primary_risk_factor: String,
    /// One-sentence reasoning.
    pub reasoning: String,
}

impl GeminiTrustResult {
    /// Convert the verdict string to a [`Verdict`] enum.
    pub fn to_verdict(&self) -> Verdict {
        match self.verdict.as_str() {
            "Allow" => Verdict::Allow,
            "Monitor" => Verdict::Monitor,
            "Deny" => Verdict::Deny,
            _ => Verdict::from_score(self.trust_score),
        }
    }
}

/// Cached decision with expiration.
#[derive(Debug, Clone)]
struct CachedDecision {
    result: GeminiTrustResult,
    expires_at: Instant,
}

/// Gemini client errors.
#[derive(Debug, thiserror::Error)]
pub enum GeminiError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("rate limited — exceeded {max_rps} requests/second")]
    RateLimited { max_rps: u32 },

    #[error("API returned non-200 status: {status} — {body}")]
    ApiError { status: u16, body: String },

    #[error("failed to parse Gemini response: {0}")]
    ParseError(String),

    #[error("request timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("API key not configured")]
    NoApiKey,
}

/// Metrics for Gemini API usage.
#[derive(Debug, Default)]
pub struct GeminiMetrics {
    pub calls_total: AtomicU64,
    pub cache_hits_total: AtomicU64,
    pub errors_total: AtomicU64,
    pub timeout_errors: AtomicU64,
    pub parse_errors: AtomicU64,
    pub total_latency_us: AtomicU64,
}

// ────────────────────────── Gemini API Request/Response ──────────────────────────

/// Gemini API request body.
#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    system_instruction: GeminiSystemInstruction,
    generation_config: GeminiGenerationConfig,
}

#[derive(Debug, Serialize)]
struct GeminiSystemInstruction {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiPart {
    text: String,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    temperature: f32,
    max_output_tokens: u32,
    #[serde(rename = "responseMimeType")]
    response_mime_type: String,
}

/// Gemini API response body.
#[derive(Debug, Deserialize)]
struct GeminiResponse {
    candidates: Option<Vec<GeminiCandidate>>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: GeminiCandidateContent,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidateContent {
    parts: Vec<GeminiPart>,
}

// ────────────────────────── User Message Builder ──────────────────────────

/// The structured user message sent per trust evaluation.
#[derive(Debug, Serialize)]
struct TrustEvalRequest {
    source: SourceInfo,
    destination: DestInfo,
    intent: String,
    session_frequency_per_min: u32,
    historical_trust_score: Option<u8>,
    behavioral_flags: Vec<String>,
    time_of_day_utc: u8,
}

#[derive(Debug, Serialize)]
struct SourceInfo {
    entity_id: String,
    entity_type: String,
    identity_age_hours: u64,
}

#[derive(Debug, Serialize)]
struct DestInfo {
    entity_id: String,
}

fn intent_code_to_string(code: u16) -> String {
    match code {
        0x0001 => "ModelInference".into(),
        0x0002 => "DataSync".into(),
        0x0003 => "FederatedLearning".into(),
        0x0004 => "ControlSignal".into(),
        0x0005 => "Negotiation".into(),
        0x0006 => "FileTransfer".into(),
        0x00FF => "Heartbeat".into(),
        _ => format!("Unknown(0x{code:04x})"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sanitize a string for inclusion in an AI prompt.
///
/// Strips potentially dangerous characters and limits length to prevent
/// prompt injection or context window overflow.
fn sanitize_for_prompt(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ' | ':'))
        .take(max_len)
        .collect()
}

fn build_user_message(ctx: &TrustContext) -> String {
    let req = TrustEvalRequest {
        source: SourceInfo {
            entity_id: hex_encode(&ctx.source_entity_id),
            entity_type: sanitize_for_prompt("AIModel", 32),
            identity_age_hours: ctx.identity_age_secs / 3600,
        },
        destination: DestInfo {
            entity_id: hex_encode(&ctx.dest_entity_id),
        },
        intent: sanitize_for_prompt(&intent_code_to_string(ctx.intent_code), 64),
        session_frequency_per_min: ctx.session_frequency,
        historical_trust_score: ctx.historical_score,
        behavioral_flags: ctx
            .behavioral_flags
            .iter()
            .map(|f| sanitize_for_prompt(&format!("{f:?}"), 64))
            .collect(),
        time_of_day_utc: ctx.time_of_day,
    };

    // Unwrap is safe here — TrustEvalRequest is always serializable
    serde_json::to_string_pretty(&req).unwrap_or_default()
}

// ────────────────────────── Client ──────────────────────────

/// Configuration for the Gemini client.
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub api_key: String,
    pub model: String,
    pub timeout_ms: u64,
    pub cache_ttl_secs: u64,
    pub max_rps: u32,
}

impl Default for GeminiConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            model: "gemini-2.0-flash".into(),
            timeout_ms: 4000,
            cache_ttl_secs: 60,
            max_rps: 100,
        }
    }
}

/// Gemini API client with caching, rate limiting, and metrics.
pub struct GeminiClient {
    api_key: String,
    model: String,
    http_client: Client,
    cache: Arc<DashMap<u64, CachedDecision>>,
    rate_limiter: Arc<
        GovRateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
    cache_ttl: Duration,
    max_rps: u32,
    metrics: Arc<GeminiMetrics>,
}

impl std::fmt::Debug for GeminiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeminiClient")
            .field("model", &self.model)
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

impl GeminiClient {
    /// Create a new Gemini client from configuration.
    pub fn new(config: GeminiConfig) -> Result<Self, GeminiError> {
        if config.api_key.is_empty() {
            return Err(GeminiError::NoApiKey);
        }

        let http_client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| GeminiError::HttpError(e.to_string()))?;

        let quota = Quota::per_second(
            NonZeroU32::new(config.max_rps).unwrap_or(NonZeroU32::new(100).expect("100 > 0")),
        );
        let rate_limiter = Arc::new(GovRateLimiter::direct(quota));

        Ok(Self {
            api_key: config.api_key,
            model: config.model,
            http_client,
            cache: Arc::new(DashMap::new()),
            rate_limiter,
            cache_ttl: Duration::from_secs(config.cache_ttl_secs),
            max_rps: config.max_rps,
            metrics: Arc::new(GeminiMetrics::default()),
        })
    }

    /// Create a mock/no-op client for rules-only mode.
    pub fn noop() -> Self {
        Self {
            api_key: String::new(),
            model: String::new(),
            http_client: Client::new(),
            cache: Arc::new(DashMap::new()),
            rate_limiter: Arc::new(GovRateLimiter::direct(Quota::per_second(
                NonZeroU32::new(1).expect("1 > 0"),
            ))),
            cache_ttl: Duration::from_secs(0),
            max_rps: 1,
            metrics: Arc::new(GeminiMetrics::default()),
        }
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &GeminiMetrics {
        &self.metrics
    }

    /// Hash a TrustContext for cache lookups.
    fn context_hash(ctx: &TrustContext) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(ctx.source_entity_id);
        hasher.update(ctx.dest_entity_id);
        hasher.update(ctx.intent_code.to_le_bytes());
        hasher.update(ctx.session_frequency.to_le_bytes());
        if let Some(score) = ctx.historical_score {
            hasher.update([score]);
        }
        let hash = hasher.finalize();
        u64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8]))
    }

    /// Evaluate trust via Gemini API, with caching and rate limiting.
    #[tracing::instrument(skip(self, ctx), fields(model = %self.model))]
    pub async fn evaluate_trust(
        &self,
        ctx: &TrustContext,
    ) -> Result<GeminiTrustResult, GeminiError> {
        self.metrics.calls_total.fetch_add(1, Ordering::Relaxed);
        let call_start = Instant::now();

        // Step 1: Check cache
        let cache_key = Self::context_hash(ctx);
        if let Some(cached) = self.cache.get(&cache_key) {
            if cached.expires_at > Instant::now() {
                self.metrics
                    .cache_hits_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(cache_key, "Gemini cache hit");
                return Ok(cached.result.clone());
            }
            // Expired — drop and re-evaluate
            drop(cached);
            self.cache.remove(&cache_key);
        }

        // Step 2: Rate limit check
        if self.rate_limiter.check().is_err() {
            self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            return Err(GeminiError::RateLimited {
                max_rps: self.max_rps,
            });
        }

        // Step 3: Build request
        let user_message = build_user_message(ctx);

        let api_url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let request_body = GeminiRequest {
            contents: vec![GeminiContent {
                parts: vec![GeminiPart { text: user_message }],
            }],
            system_instruction: GeminiSystemInstruction {
                parts: vec![GeminiPart {
                    text: GEMINI_SYSTEM_PROMPT.to_string(),
                }],
            },
            generation_config: GeminiGenerationConfig {
                temperature: 0.1, // Low temperature for deterministic output
                max_output_tokens: 256,
                response_mime_type: "application/json".to_string(),
            },
        };

        // Step 4: Make API call
        let response = self
            .http_client
            .post(&api_url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                if e.is_timeout() {
                    self.metrics.timeout_errors.fetch_add(1, Ordering::Relaxed);
                    GeminiError::Timeout {
                        timeout_ms: call_start.elapsed().as_millis() as u64,
                    }
                } else {
                    GeminiError::HttpError(e.to_string())
                }
            })?;

        let status = response.status().as_u16();
        if status != 200 {
            let body = response.text().await.unwrap_or_default();
            self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            return Err(GeminiError::ApiError { status, body });
        }

        // Step 5: Parse response
        let body_text = response.text().await.map_err(|e| {
            self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            GeminiError::ParseError(format!("failed to read response body: {e}"))
        })?;

        let gemini_response: GeminiResponse = serde_json::from_str(&body_text).map_err(|e| {
            self.metrics.parse_errors.fetch_add(1, Ordering::Relaxed);
            self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            GeminiError::ParseError(format!("JSON parse error: {e}, body: {body_text}"))
        })?;

        // Extract the text content from the first candidate
        let text_content = gemini_response
            .candidates
            .as_ref()
            .and_then(|c| c.first())
            .and_then(|c| c.content.parts.first())
            .map(|p| p.text.clone())
            .ok_or_else(|| {
                self.metrics.parse_errors.fetch_add(1, Ordering::Relaxed);
                self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                GeminiError::ParseError("no content in Gemini response".into())
            })?;

        // Parse the trust result from the text
        let result: GeminiTrustResult = serde_json::from_str(&text_content).map_err(|e| {
            self.metrics.parse_errors.fetch_add(1, Ordering::Relaxed);
            self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            GeminiError::ParseError(format!(
                "failed to parse trust result: {e}, text: {text_content}"
            ))
        })?;

        // Step 6: Cache the result
        self.cache.insert(
            cache_key,
            CachedDecision {
                result: result.clone(),
                expires_at: Instant::now() + self.cache_ttl,
            },
        );

        // Record latency
        let latency_us = call_start.elapsed().as_micros() as u64;
        self.metrics
            .total_latency_us
            .fetch_add(latency_us, Ordering::Relaxed);

        tracing::info!(
            trust_score = result.trust_score,
            verdict = %result.verdict,
            confidence = result.confidence,
            latency_us,
            "Gemini trust evaluation complete"
        );

        Ok(result)
    }

    /// Invalidate a cached decision for a given context.
    pub fn invalidate_cache(&self, ctx: &TrustContext) {
        let cache_key = Self::context_hash(ctx);
        self.cache.remove(&cache_key);
    }

    /// Clear all cached decisions.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get the number of cached entries.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::BehaviorFlag;

    fn test_context() -> TrustContext {
        TrustContext {
            source_entity_id: [1u8; 32],
            dest_entity_id: [2u8; 32],
            intent_code: 0x0001,
            identity_age_secs: 3600 * 24,
            historical_score: Some(180),
            behavioral_flags: vec![BehaviorFlag::Normal],
            time_of_day: 14,
            session_frequency: 10,
        }
    }

    #[test]
    fn test_context_hash_deterministic() {
        let ctx = test_context();
        let h1 = GeminiClient::context_hash(&ctx);
        let h2 = GeminiClient::context_hash(&ctx);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_context_hash_different_for_different_inputs() {
        let ctx1 = test_context();
        let mut ctx2 = test_context();
        ctx2.intent_code = 0x0004; // ControlSignal
        assert_ne!(
            GeminiClient::context_hash(&ctx1),
            GeminiClient::context_hash(&ctx2)
        );
    }

    #[test]
    fn test_user_message_format() {
        let ctx = test_context();
        let msg = build_user_message(&ctx);
        assert!(msg.contains("ModelInference"));
        assert!(msg.contains("entity_id"));
        assert!(msg.contains("identity_age_hours"));
    }

    #[test]
    fn test_gemini_result_to_verdict() {
        let result = GeminiTrustResult {
            verdict: "Allow".into(),
            trust_score: 200,
            confidence: 0.95,
            primary_risk_factor: "none".into(),
            reasoning: "Trusted entity".into(),
        };
        assert_eq!(result.to_verdict(), Verdict::Allow);

        let result = GeminiTrustResult {
            verdict: "Deny".into(),
            trust_score: 10,
            confidence: 0.99,
            primary_risk_factor: "anomaly".into(),
            reasoning: "Bad actor".into(),
        };
        assert_eq!(result.to_verdict(), Verdict::Deny);
    }

    #[test]
    fn test_noop_client_creation() {
        let client = GeminiClient::noop();
        assert_eq!(client.cache_size(), 0);
    }

    #[test]
    fn test_no_api_key_error() {
        let config = GeminiConfig::default();
        let result = GeminiClient::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_intent_code_to_string() {
        assert_eq!(intent_code_to_string(0x0001), "ModelInference");
        assert_eq!(intent_code_to_string(0x0004), "ControlSignal");
        assert_eq!(intent_code_to_string(0x00FF), "Heartbeat");
        assert!(intent_code_to_string(0x9999).contains("Unknown"));
    }
}
