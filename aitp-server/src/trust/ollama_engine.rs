use super::{SessionContext, TrustResult, TrustVerdict};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// System prompt for Ollama AI trust evaluation.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaTrustResponse {
    pub trust_score: u8,
    pub verdict: String,
    pub primary_risk: String,
    pub reasoning: String,
    pub confidence: f64,
    #[serde(default)]
    pub behavioral_flags: Vec<String>,
}

#[derive(Clone)]
pub struct OllamaTrustEngine {
    pub client: Arc<reqwest::Client>,
    pub endpoint: String,
    pub model: String,
}

impl OllamaTrustEngine {
    pub fn new(client: Arc<reqwest::Client>, endpoint: &str, model: &str) -> Self {
        Self {
            client,
            endpoint: endpoint.to_string(),
            model: model.to_string(),
        }
    }

    pub async fn evaluate(&self, ctx: &SessionContext) -> Result<TrustResult, String> {
        let ctx_json = serde_json::to_string(ctx)
            .map_err(|e| format!("Failed to serialize context: {}", e))?;

        let url = format!("{}/api/generate", self.endpoint);
        let prompt = format!("Evaluate this session:\n{}", ctx_json);

        let payload = serde_json::json!({
            "model": self.model,
            "system": TRUST_SYSTEM_PROMPT,
            "prompt": prompt,
            "format": "json",
            "stream": false,
            "options": {
                "temperature": 0.1
            }
        });

        let start = std::time::Instant::now();

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("OllamaError: {}", e))?;

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        crate::metrics::OLLAMA_REQUEST_DURATION.observe(latency_ms / 1000.0);

        if !response.status().is_success() {
            crate::metrics::record_ollama_call(&self.model, "error", latency_ms);
            return Err(format!("Ollama API returned HTTP {}", response.status()));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse Ollama JSON response: {}", e))?;

        let response_text = body["response"]
            .as_str()
            .ok_or_else(|| "Missing 'response' field in Ollama response".to_string())?;

        let text = response_text.trim();
        let ollama_result: OllamaTrustResponse = match serde_json::from_str(text) {
            Ok(res) => res,
            Err(e) => {
                let start_idx = text.find('{');
                let end_idx = text.rfind('}');

                if let (Some(s), Some(e_idx)) = (start_idx, end_idx) {
                    let cleaned = &text[s..=e_idx];
                    serde_json::from_str::<OllamaTrustResponse>(cleaned).map_err(|_| {
                        format!("Failed to parse cleaned Ollama JSON: {} — raw: {}", e, text)
                    })?
                } else {
                    crate::metrics::record_ollama_call(&self.model, "parse", latency_ms);
                    return Err(format!(
                        "No JSON object found in Ollama response: {} — raw: {}",
                        e, text
                    ));
                }
            }
        };

        crate::metrics::record_ollama_call(&self.model, "success", latency_ms);
        crate::metrics::TRUST_VERDICT_SOURCE.with_label_values(&["ollama"]).inc();

        Ok(TrustResult {
            trust_score: ollama_result.trust_score,
            verdict: TrustVerdict::from_str_loose(&ollama_result.verdict),
            primary_risk: ollama_result.primary_risk,
            reasoning: ollama_result.reasoning,
            confidence: ollama_result.confidence as f32,
            behavioral_flags: ollama_result.behavioral_flags,
            evaluation_ms: latency_ms,
            source: "ollama".to_string(),
        })
    }

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
