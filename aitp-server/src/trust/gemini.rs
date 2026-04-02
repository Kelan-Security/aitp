use super::{SessionContext, TrustResult, TrustVerdict};
use serde::{Deserialize, Serialize};

/// System prompt for Gemini AI trust evaluation.
const TRUST_SYSTEM_PROMPT: &str = r#"
You are AITP's AI Trust Engine. Evaluate network session trust in real-time.
You receive session context as JSON. Return ONLY valid JSON, no markdown:
{
  "trust_score": <integer 0-255>,
  "verdict": "Allow" | "Monitor" | "Deny",
  "primary_risk": "<2-5 words describing main concern>",
  "reasoning": "<one clear sentence>",
  "confidence": <float 0.0-1.0>,
  "behavioral_flags": ["flag1", "flag2"]
}

Scoring rules:
- Unknown entity_id → score 0, verdict Deny, always
- New entity (age < 1 hour) → cap score at 100
- ControlSignal intent → subtract 25 from score
- Behavioral anomaly flags → subtract 30 per flag
- High peer reputation + established entity → add up to 30
- Consistent with historical patterns → add 20
- Verdict: Allow if score >= 128, Monitor if 64-127, Deny if < 64
"#;

/// Gemini AI trust evaluation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiTrustResponse {
    pub trust_score: u8,
    pub verdict: String,
    pub primary_risk: String,
    pub reasoning: String,
    pub confidence: f64,
    #[serde(default)]
    pub behavioral_flags: Vec<String>,
}

/// Gemini API request structures.
#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    system_instruction: GeminiSystemInstruction,
    #[serde(rename = "generationConfig")]
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
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
    #[serde(rename = "responseMimeType")]
    response_mime_type: String,
}

/// Gemini API response structures.
#[derive(Debug, Deserialize)]
struct GeminiApiResponse {
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

/// Gemini 1.5 Flash trust engine client.
pub struct GeminiTrustEngine {
    pub client: std::sync::Arc<crate::ai::GeminiClient>,
    pub model: String,
}

impl GeminiTrustEngine {
    pub fn new(client: std::sync::Arc<crate::ai::GeminiClient>, model: &str) -> Self {
        Self {
            client,
            model: model.to_string(),
        }
    }

    /// Evaluate trust via Gemini AI.
    pub async fn evaluate(&self, ctx: &SessionContext) -> Result<TrustResult, String> {
        let ctx_json = serde_json::to_string(ctx)
            .map_err(|e| format!("Failed to serialize context: {}", e))?;

        let prompt = format!("Evaluate this session:\n{}", ctx_json);
        let gemini_start = std::time::Instant::now();
        let mut text = String::new();
        let mut success = false;
        let mut retries = 0;

        while retries < 3 {
            // Layer 2: Global response timeout (2000ms max for an attempt)
            let attempt_future = tokio::time::timeout(
                std::time::Duration::from_millis(2000), 
                self.client.generate_content(&self.model, Some(TRUST_SYSTEM_PROMPT), &prompt, 0.1, true)
            );

            match attempt_future.await {
                Ok(Ok(response)) => {
                    text = response;
                    success = true;
                    break;
                }
                Ok(Err(api_err)) => {
                    // API request finished within timeout but yielded internal error (ex: 429)
                    tracing::warn!("Gemini API Error on attempt {}: {}", retries + 1, api_err);
                    retries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                Err(_) => {
                    // Layer 2 Drop: Full 2000ms boundary breached, abort attempt
                    tracing::warn!("Gemini API Timeout (2000ms) on attempt {}", retries + 1);
                    crate::metrics::GEMINI_TIMEOUT_TOTAL.inc();
                    retries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            }
        }

        if !success {
            return Err("GeminiTimeout: Exhausted all retries or breached temporal deadlines".to_string());
        }

        let latency_ms = gemini_start.elapsed().as_secs_f64() * 1000.0;
        crate::metrics::GEMINI_REQUEST_DURATION.observe(latency_ms / 1000.0);

        let gemini_result: GeminiTrustResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(e) => {
                let start = text.find('{');
                let end = text.rfind('}');

                if let (Some(s), Some(e)) = (start, end) {
                    let cleaned = &text[s..=e];
                    serde_json::from_str::<GeminiTrustResponse>(cleaned).map_err(|_| {
                        format!("Failed to parse cleaned Gemini JSON: {} — raw: {}", e, text)
                    })?
                } else {
                    return Err(format!(
                        "No JSON object found in Gemini response: {} — raw: {}",
                        e, text
                    ));
                }
            }
        };

        crate::metrics::TRUST_VERDICT_SOURCE.with_label_values(&["gemini"]).inc();

        Ok(TrustResult {
            trust_score: gemini_result.trust_score,
            verdict: TrustVerdict::from_str_loose(&gemini_result.verdict),
            primary_risk: gemini_result.primary_risk,
            reasoning: gemini_result.reasoning,
            confidence: gemini_result.confidence as f32,
            behavioral_flags: gemini_result.behavioral_flags,
            evaluation_ms: latency_ms,
            source: "gemini".to_string(),
        })
    }

    /// Verify the API key by making a test trust evaluation.
    pub async fn verify_key(&self) -> Result<TrustResult, String> {
        let test_ctx = SessionContext {
            source_entity_id: "test_entity_abc123".to_string(),
            org_id: "test_org".to_string(),
            source_entity_type: "workstation".to_string(),
            source_department: Some("Engineering".to_string()),
            source_clearance: 0,
            dest_entity_id: "test_server_def456".to_string(),
            dest_entity_type: "server".to_string(),
            intent: "ModelInference".to_string(),
            entity_age_hours: 720.0,
            session_count_24h: 12,
            avg_trust_score: 180.0,
            known_peer: true,
            behavioral_flags: vec![],
            time_of_day_hour: 14,
        };

        self.evaluate(&test_ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::GeminiClient;
    use std::sync::Arc;

    #[test]
    fn test_system_prompt_not_empty() {
        assert!(!TRUST_SYSTEM_PROMPT.is_empty());
        assert!(TRUST_SYSTEM_PROMPT.contains("trust_score"));
    }

    #[test]
    fn test_gemini_engine_creation() {
        let client = Arc::new(GeminiClient::new("test_key"));
        let engine = GeminiTrustEngine::new(client, "gemini-2.5-flash");
        assert_eq!(engine.model, "gemini-2.5-flash");
    }

    #[test]
    fn test_gemini_response_deserialize() {
        let json = r#"{
            "trust_score": 200,
            "verdict": "Allow",
            "primary_risk": "No concerns",
            "reasoning": "Established entity with high trust history",
            "confidence": 0.95,
            "behavioral_flags": []
        }"#;

        let result: GeminiTrustResponse = serde_json::from_str(json).unwrap();
        assert_eq!(result.trust_score, 200);
        assert_eq!(result.verdict, "Allow");
        assert_eq!(result.confidence, 0.95);
    }
}
