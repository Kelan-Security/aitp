use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustVerdict {
    pub verdict: String,
    pub confidence: f32,
    pub reason: String,
}

pub fn create_client() -> Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(
            std::env::var("OLLAMA_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8),
        ))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

pub async fn evaluate_trust(
    client: &Client,
    intent: &str,
    entity_id: &str,
    history: &str,
    anomalies: &str,
) -> Result<TrustVerdict> {
    let model = std::env::var("OLLAMA_MODEL")
        .unwrap_or_else(|_| "gemma4:latest".to_string());
    let endpoint = std::env::var("OLLAMA_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:11434".to_string());

    let prompt = format!(
        r#"You are a network security AI. Analyze this session.

Intent: {}
Entity: {}
History: {}
Anomalies: {}

Respond ONLY with valid JSON (no markdown, no explanation):
{{"verdict":"ALLOW","confidence":0.95,"reason":"explanation here"}}

verdict must be exactly: ALLOW, DENY, or MONITOR
confidence must be 0.0 to 1.0"#,
        intent, entity_id, history, anomalies
    );

    debug!("Calling Ollama at {} model={}", endpoint, model);

    let resp = match client
        .post(format!("{}/api/generate", endpoint))
        .json(&OllamaRequest {
            model,
            prompt,
            stream: false,
        })
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Ollama unreachable: {}. Using fallback.", e);
            return Ok(fallback_verdict("ollama_unreachable"));
        }
    };

    let body: OllamaResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            warn!("Ollama response parse failed: {}. Using fallback.", e);
            return Ok(fallback_verdict("response_parse_error"));
        }
    };

    Ok(parse_verdict(&body.response))
}

fn parse_verdict(response: &str) -> TrustVerdict {
    let json_str = match (response.find('{'), response.rfind('}')) {
        (Some(start), Some(end)) if end > start => &response[start..=end],
        _ => {
            warn!("No JSON found in Ollama response: {}", response);
            return fallback_verdict("no_json_in_response");
        }
    };

    match serde_json::from_str::<TrustVerdict>(json_str) {
        Ok(mut v) => {
            v.verdict = v.verdict.to_uppercase();
            if !["ALLOW", "DENY", "MONITOR"].contains(&v.verdict.as_str()) {
                v.verdict = "MONITOR".to_string();
            }
            v.confidence = v.confidence.clamp(0.0, 1.0);
            v
        }
        Err(e) => {
            warn!("Verdict JSON parse failed: {}. Raw: {}", e, json_str);
            fallback_verdict("json_parse_failed")
        }
    }
}

fn fallback_verdict(reason: &str) -> TrustVerdict {
    TrustVerdict {
        verdict: "MONITOR".to_string(),
        confidence: 0.3,
        reason: format!("fallback:{}", reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clean_json() {
        let v = parse_verdict(
            r#"{"verdict":"ALLOW","confidence":0.95,"reason":"ok"}"#
        );
        assert_eq!(v.verdict, "ALLOW");
        assert_eq!(v.confidence, 0.95);
    }

    #[test]
    fn test_parse_json_with_surrounding_text() {
        let v = parse_verdict(
            r#"Sure! {"verdict":"DENY","confidence":0.8,"reason":"bad"}"#
        );
        assert_eq!(v.verdict, "DENY");
    }

    #[test]
    fn test_invalid_verdict_becomes_monitor() {
        let v = parse_verdict(
            r#"{"verdict":"MAYBE","confidence":0.5,"reason":"x"}"#
        );
        assert_eq!(v.verdict, "MONITOR");
    }

    #[test]
    fn test_no_json_returns_fallback() {
        let v = parse_verdict("This is not json at all");
        assert_eq!(v.verdict, "MONITOR");
        assert!(v.reason.starts_with("fallback:"));
    }

    #[test]
    fn test_confidence_clamped() {
        let v = parse_verdict(
            r#"{"verdict":"ALLOW","confidence":1.5,"reason":"x"}"#
        );
        assert!(v.confidence <= 1.0);
    }
}
