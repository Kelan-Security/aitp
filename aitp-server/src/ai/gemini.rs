// AITP — ai/gemini.rs
// Production-grade client for Google Gemini 1.5 Flash/Pro.
// Supports v1beta/generateContent with robust parsing and retries.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, warn};

/// Gemini API request and response structures.
#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "systemInstruction")]
    system_instruction: Option<GeminiSystemInstruction>,
    #[serde(rename = "generationConfig")]
    generation_config: GeminiGenerationConfig,
}

#[derive(Debug, Serialize)]
struct GeminiSystemInstruction {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none", rename = "responseMimeType")]
    response_mime_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeminiApiResponse {
    candidates: Option<Vec<GeminiCandidate>>,
    error: Option<GeminiApiError>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: GeminiCandidateContent,
    #[serde(rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidateContent {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Deserialize)]
struct GeminiApiError {
    code: i32,
    message: String,
    status: String,
}

/// Centralized, production-grade Gemini client.
pub struct GeminiClient {
    api_key: String,
    client: reqwest::Client,
    max_retries: u32,
    timeout: Duration,
}

impl GeminiClient {
    /// Create a new Gemini client.
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30)) // overall timeout
                .build()
                .unwrap_or_default(),
            max_retries: 3,
            timeout: Duration::from_secs(10), // per-request timeout
        }
    }

    /// Primary entry point for generating content from a prompt.
    pub async fn generate_content(
        &self,
        model: &str,
        system_prompt: Option<&str>,
        prompt: &str,
        temperature: f32,
        json_output: bool,
    ) -> Result<String, String> {
        if self.api_key.is_empty() {
            return Err("Gemini API key is not configured.".to_string());
        }

        let system_instruction = system_prompt.map(|s| GeminiSystemInstruction {
            parts: vec![GeminiPart { text: s.to_string() }],
        });

        let contents = vec![GeminiContent {
            role: None,
            parts: vec![GeminiPart {
                text: prompt.to_string(),
            }],
        }];

        let request = GeminiRequest {
            contents,
            system_instruction,
            generation_config: GeminiGenerationConfig {
                temperature,
                max_output_tokens: 4096,
                response_mime_type: if json_output {
                    Some("application/json".to_string())
                } else {
                    None
                },
            },
        };

        self.execute_with_retry(model, request).await
    }

    /// Execute a chat conversation with role history.
    pub async fn chat(
        &self,
        model: &str,
        system_prompt: Option<&str>,
        history: Vec<serde_json::Value>,
        temperature: f32,
    ) -> Result<String, String> {
        if self.api_key.is_empty() {
            return Err("Gemini API key is not configured.".to_string());
        }

        let mut contents = Vec::new();
        for turn in history {
            let content: GeminiContent = serde_json::from_value(turn)
                .map_err(|e| format!("Invalid turn in history: {}", e))?;
            contents.push(content);
        }

        let request = GeminiRequest {
            contents,
            system_instruction: system_prompt.map(|s| GeminiSystemInstruction {
                parts: vec![GeminiPart { text: s.to_string() }],
            }),
            generation_config: GeminiGenerationConfig {
                temperature,
                max_output_tokens: 4096,
                response_mime_type: None,
            },
        };

        self.execute_with_retry(model, request).await
    }

    /// Internal execution engine with exponential backoff retries.
    async fn execute_with_retry(
        &self,
        model: &str,
        request: GeminiRequest,
    ) -> Result<String, String> {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            model, self.api_key
        );

        let mut attempts = 0;
        let mut last_error = String::new();

        while attempts < self.max_retries {
            attempts += 1;
            let start = std::time::Instant::now();

            match self.client.post(&url).timeout(self.timeout).json(&request).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

                    if status.is_success() {
                        let api_resp: GeminiApiResponse = resp.json().await.map_err(|e| {
                            format!("Failed to parse Gemini success response: {}", e)
                        })?;

                        if let Some(error) = api_resp.error {
                            last_error = format!(
                                "Gemini API Error [{} {}]: {}",
                                error.code, error.status, error.message
                            );
                            warn!("Gemini API error during success status: {}", last_error);
                        } else {
                            let candidate = api_resp
                                .candidates
                                .and_then(|mut c| if c.is_empty() { None } else { Some(c.remove(0)) });

                            if let Some(candidate) = candidate {
                                // Log finish_reason for full AI observability
                                let finish_reason = candidate.finish_reason.as_deref().unwrap_or("UNKNOWN");
                                if finish_reason != "STOP" {
                                    warn!(
                                        model = model,
                                        finish_reason = finish_reason,
                                        "Gemini candidate did not finish with STOP — check for truncation or content filtering"
                                    );
                                } else {
                                    tracing::debug!(
                                        model = model,
                                        finish_reason = finish_reason,
                                        "Gemini call completed"
                                    );
                                }

                                let text = candidate
                                    .content
                                    .parts
                                    .into_iter()
                                    .next()
                                    .map(|p| p.text)
                                    .ok_or_else(|| "Empty response parts from Gemini candidate".to_string())?;

                                crate::metrics::record_gemini_call(model, "success", latency_ms);
                                return Ok(text);
                            } else {
                                last_error = "No candidates returned by Gemini".to_string();
                                warn!("{}", last_error);
                            }
                        }
                    } else if status.as_u16() == 429 {
                        last_error = "Rate limit reached (429)".to_string();
                        crate::metrics::record_gemini_call(model, "rate_limit", latency_ms);
                        warn!("Gemini 429: Rate limit hit. Retry {}/{}", attempts, self.max_retries);
                    } else if status.as_u16() == 404 {
                        let body = resp.text().await.unwrap_or_default();
                        crate::metrics::record_gemini_call(model, "not_found", latency_ms);
                        error!("Gemini 404: Model '{}' not found. Body: {}", model, body);
                        return Err(format!("Model '{}' not found (404). Check AITP_GEMINI_MODEL.", model));
                    } else if status.as_u16() == 403 {
                        let body = resp.text().await.unwrap_or_default();
                        crate::metrics::record_gemini_call(model, "auth", latency_ms);
                        error!("Gemini 403: Forbidden. Check API Key. Body: {}", body);
                        return Err("Gemini API key is invalid or lacks necessary permissions (403).".to_string());
                    } else {
                        last_error = format!("API returned error status {}", status);
                        crate::metrics::record_gemini_call(model, "error", latency_ms);
                        warn!("Gemini {} error. Retry {}/{}", status, attempts, self.max_retries);
                    }
                }
                Err(e) => {
                    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                    last_error = format!("Network/Timeout error: {}", e);
                    let err_type = if e.is_timeout() { "timeout" } else { "network" };
                    crate::metrics::record_gemini_call(model, err_type, latency_ms);
                    warn!("Gemini {} error. Retry {}/{}", err_type, attempts, self.max_retries);
                }
            }

            if attempts < self.max_retries {
                let backoff_ms = 2u64.pow(attempts) * 200; // 400ms, 800ms, 1600ms...
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }

        Err(format!("Gemini request failed after {} attempts. Last error: {}", self.max_retries, last_error))
    }
}
