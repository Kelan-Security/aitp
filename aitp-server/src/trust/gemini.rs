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

/// Gemini 2.5 Flash trust engine client.
pub struct GeminiTrustEngine {
    api_key: String,
    model: String,
    client: reqwest::Client,
}

impl GeminiTrustEngine {
    pub fn new(api_key: &str, model: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(4000))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Evaluate trust via Gemini API.
    pub async fn evaluate(&self, ctx: &SessionContext) -> Result<TrustResult, String> {
        if self.api_key.is_empty() {
            return Err("Gemini API key not configured".to_string());
        }

        let ctx_json = serde_json::to_string(ctx)
            .map_err(|e| format!("Failed to serialize context: {}", e))?;

        let request = GeminiRequest {
            contents: vec![GeminiContent {
                parts: vec![GeminiPart {
                    text: format!("Evaluate this session:\n{}", ctx_json),
                }],
            }],
            system_instruction: GeminiSystemInstruction {
                parts: vec![GeminiPart {
                    text: TRUST_SYSTEM_PROMPT.to_string(),
                }],
            },
            generation_config: GeminiGenerationConfig {
                temperature: 0.1,
                max_output_tokens: 256,
                response_mime_type: "application/json".to_string(),
            },
        };

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Gemini API request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Gemini API returned {}: {}", status, body));
        }

        let api_response: GeminiApiResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse Gemini response: {}", e))?;

        let text = api_response
            .candidates
            .and_then(|c| c.into_iter().next())
            .and_then(|c| c.content.parts.into_iter().next())
            .map(|p| p.text)
            .ok_or_else(|| "Empty response from Gemini".to_string())?;

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

        Ok(TrustResult {
            trust_score: gemini_result.trust_score,
            verdict: TrustVerdict::from_str_loose(&gemini_result.verdict),
            primary_risk: gemini_result.primary_risk,
            reasoning: gemini_result.reasoning,
            confidence: gemini_result.confidence as f32,
            behavioral_flags: gemini_result.behavioral_flags,
            evaluation_ms: 0.0,
            source: "gemini".to_string(),
        })
    }

    /// Verify the API key by making a test trust evaluation.
    pub async fn verify_key(&self) -> Result<TrustResult, String> {
        let test_ctx = SessionContext {
            source_entity_id: "test_entity_abc123".to_string(),
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

    #[test]
    fn test_system_prompt_not_empty() {
        assert!(!TRUST_SYSTEM_PROMPT.is_empty());
        assert!(TRUST_SYSTEM_PROMPT.contains("trust_score"));
    }

    #[test]
    fn test_gemini_engine_creation() {
        let engine = GeminiTrustEngine::new("test_key", "gemini-2.5-flash");
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
