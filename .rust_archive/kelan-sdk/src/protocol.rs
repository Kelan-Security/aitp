use serde::{Deserialize, Serialize};



/// Result of the AI trust evaluation for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResult {
    /// 0–255. Below 64 = Deny. 64–127 = Monitor. 128+ = Allow.
    pub trust_score: u8,
    pub verdict: TrustVerdict,
    /// Natural language reasoning from Ollama
    pub reasoning: String,
    /// Confidence of the AI evaluation, 0.0–1.0
    pub confidence: f32,
    /// Flags raised during evaluation
    pub anomaly_flags: Vec<String>,
    /// Round-trip latency of the full handshake in milliseconds
    pub latency_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustVerdict {
    Allow,
    Monitor,
    Deny,
}
