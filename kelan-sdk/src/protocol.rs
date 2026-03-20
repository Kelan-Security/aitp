use serde::{Deserialize, Serialize};

/// The declared purpose of a network session.
/// Signed and irrevocably logged for every connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IntentCode {
    ModelInference,
    DataSync,
    ControlSignal,
    Telemetry,
    AgentCoordinate,
    FileTransfer,
    Heartbeat,
    Unknown,
}

/// Result of the AI trust evaluation for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResult {
    /// 0–255. Below 64 = Deny. 64–127 = Monitor. 128+ = Allow.
    pub trust_score: u8,
    pub verdict: TrustVerdict,
    /// Natural language reasoning from Gemini 2.5
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
