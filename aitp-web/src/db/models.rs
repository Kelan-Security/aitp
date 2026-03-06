use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub industry: Option<String>,
    #[serde(skip_serializing)]
    pub gemini_api_key_enc: Option<String>,
    #[serde(skip_serializing)]
    pub claude_api_key_enc: Option<String>,
    #[serde(skip_serializing)]
    pub openai_api_key_enc: Option<String>,
    pub ai_provider: String,
    pub ai_model: String,
    pub trust_mode: String,
    pub created_at: i64,
    pub last_login: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ServerNode {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub listen_address: String,
    pub listen_port: i64,
    pub entity_id: String,
    pub public_key: String,
    #[serde(skip_serializing)]
    pub private_key_path: String,
    pub status: String, // "online" | "offline"
    pub client_count: i64,
    pub session_count: i64,
    pub last_seen: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ClientNode {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub entity_id: String,
    pub public_key: String,
    #[serde(skip_serializing)]
    pub private_key_path: String,
    pub allowed_intents: String, // JSON array string
    pub trust_score: i64,
    pub session_count: i64,
    pub blocked_count: i64,
    pub last_seen: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub org_id: String,
    pub server_node_id: String,
    pub client_node_id: Option<String>,
    pub client_entity_id: String,
    pub client_ip: String,
    pub client_port: i64,
    pub intent: String,
    pub trust_score: i64,
    pub verdict: String,
    pub ai_provider: Option<String>,
    pub ai_latency_ms: Option<i64>,
    pub ai_reasoning: Option<String>,
    pub status: String,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub close_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEvent {
    pub id: String,
    pub org_id: Option<String>,
    pub event_type: String,
    pub severity: String,
    pub source_ip: Option<String>,
    pub entity_id: Option<String>,
    pub session_id: Option<String>,
    pub description: String,
    pub metadata: Option<String>,
    pub created_at: i64,
}

// ── Request types ──────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SignupReq {
    pub org_name: String,
    pub email: String,
    pub password: String,
    pub industry: Option<String>,
    pub gemini_api_key: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct SigninReq {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Deserialize)]
pub struct CreateServerReq {
    pub name: String,
    pub listen_address: Option<String>,
    pub listen_port: Option<u16>,
}
#[derive(Debug, Deserialize)]
pub struct CreateClientReq {
    pub name: String,
    pub allowed_intents: Vec<String>,
}
#[derive(Debug, Deserialize)]
pub struct UpdateAiConfigReq {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub trust_mode: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct VerifyKeyReq {
    pub provider: String,
    pub model: String,
    pub api_key: String,
}

// ── Response types ─────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AuthResp {
    pub token: String,
    pub org: Organization,
}

#[derive(Debug, Serialize)]
pub struct StatsResp {
    pub active_sessions: i64,
    pub total_sessions: i64,
    pub avg_trust_score: Option<f64>,
    pub blocked_today: i64,
    pub ai_calls_today: i64,
    pub avg_ai_latency_ms: Option<f64>,
    pub server_nodes_online: i64,
    pub client_nodes_total: i64,
    pub uptime_seconds: u64,
}

// ── WebSocket events — these are what the frontend receives ─────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    SessionEstablished {
        session_id: String,
        client_entity_id: String,
        client_ip: String,
        intent: String,
        trust_score: i64,
        verdict: String,
        ai_provider: String,
        ai_latency_ms: i64,
        ts: String,
    },
    SessionClosed {
        session_id: String,
        reason: String,
        duration_secs: i64,
        bytes_tx: i64,
        bytes_rx: i64,
        ts: String,
    },
    TrustEval {
        session_id: String,
        score: i64,
        verdict: String,
        provider: String,
        latency_ms: i64,
        reasoning: String,
        ts: String,
    },
    PacketFlow {
        session_id: String,
        direction: String,
        bytes: i64,
        intent: String,
        trust: i64,
        ts: String,
    },
    Alert {
        alert_type: String,
        severity: String,
        source_ip: String,
        description: String,
        ts: String,
    },
    Log {
        level: String,
        message: String,
        ts: String,
    },
    Stats {
        active_sessions: i64,
        avg_trust: Option<f64>,
        blocked_today: i64,
        ai_calls: i64,
        uptime_secs: u64,
    },
    Connected {
        org_id: String,
        org_name: String,
    },
}
