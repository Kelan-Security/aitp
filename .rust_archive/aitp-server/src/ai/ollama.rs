use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct OllamaClient {
    pub endpoint: String,
    pub client: reqwest::Client,
}

impl OllamaClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn new_with_url(_api_key: &str, endpoint: &str) -> Self {
        Self::new(endpoint)
    }

    pub async fn generate_content(
        &self,
        model: &str,
        system_prompt: Option<&str>,
        prompt: &str,
        temperature: f32,
        json_output: bool,
    ) -> Result<String, String> {
        let url = format!("{}/api/generate", self.endpoint);
        let payload = serde_json::json!({
            "model": model,
            "system": system_prompt,
            "prompt": prompt,
            "format": if json_output { Some("json") } else { None },
            "stream": false,
            "options": {
                "temperature": temperature
            }
        });

        let start = std::time::Instant::now();
        let resp = self.client.post(&url).json(&payload).send().await
            .map_err(|e| format!("Ollama error: {}", e))?;

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status();

        if status.is_success() {
            let body: serde_json::Value = resp.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            let text = body["response"].as_str().unwrap_or("").to_string();
            crate::metrics::record_ollama_call(model, "success", latency_ms);
            Ok(text)
        } else {
            crate::metrics::record_ollama_call(model, "error", latency_ms);
            Err(format!("Ollama returned HTTP {}", status))
        }
    }

    pub async fn chat(
        &self,
        model: &str,
        system_prompt: Option<&str>,
        history: Vec<serde_json::Value>,
        temperature: f32,
    ) -> Result<String, String> {
        let url = format!("{}/api/chat", self.endpoint);

        let mut messages = Vec::new();
        if let Some(sys) = system_prompt {
            messages.push(serde_json::json!({
                "role": "system",
                "content": sys
            }));
        }

        for turn in history {
            let role = match turn["role"].as_str() {
                Some("model") => "assistant",
                Some(r) => r,
                _ => "user",
            };
            let content = if let Some(parts) = turn["parts"].as_array() {
                parts.first().and_then(|p| p["text"].as_str()).unwrap_or("").to_string()
            } else if let Some(content_str) = turn["content"].as_str() {
                content_str.to_string()
            } else {
                "".to_string()
            };

            messages.push(serde_json::json!({
                "role": role,
                "content": content
            }));
        }

        let payload = serde_json::json!({
            "model": model,
            "messages": messages,
            "stream": false,
            "options": {
                "temperature": temperature
            }
        });

        let start = std::time::Instant::now();
        let resp = self.client.post(&url).json(&payload).send().await
            .map_err(|e| format!("Ollama chat error: {}", e))?;

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status();

        if status.is_success() {
            let body: serde_json::Value = resp.json().await
                .map_err(|e| format!("Failed to parse chat response: {}", e))?;
            let text = body["message"]["content"].as_str().unwrap_or("").to_string();
            crate::metrics::record_ollama_call(model, "success", latency_ms);
            Ok(text)
        } else {
            crate::metrics::record_ollama_call(model, "error", latency_ms);
            Err(format!("Ollama chat returned HTTP {}", status))
        }
    }
}
