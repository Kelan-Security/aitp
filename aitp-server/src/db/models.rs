use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  DB Row Structs
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Organisation {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    #[serde(skip_serializing)]
    pub gemini_api_key_enc: Option<String>,
    pub trust_mode: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Entity {
    pub id: String,
    pub org_id: Option<String>,
    pub name: String,
    pub entity_type: String,
    pub public_key: String,
    pub department: Option<String>,
    pub clearance_level: i64,
    pub allowed_intents: String,
    pub trust_score_avg: f64,
    pub session_count: i64,
    pub blocked_count: i64,
    pub quarantined: i64,
    pub last_seen: Option<i64>,
    pub enrolled_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub org_id: String,
    pub source_entity_id: String,
    pub dest_entity_id: String,
    pub intent: String,
    pub trust_score: i64,
    pub verdict: String,
    pub ai_reasoning: Option<String>,
    pub ai_latency_ms: Option<f64>,
    pub status: String,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub anomaly_flags: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub close_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub seq: i64,
    pub org_id: String,
    pub event_type: String,
    pub severity: String,
    pub source_entity_id: Option<String>,
    pub session_id: Option<String>,
    pub description: String,
    pub metadata: String,
    pub prev_hash: Option<String>,
    pub entry_hash: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[allow(dead_code)]
pub struct DbBaseline {
    pub entity_id: String,
    pub avg_sessions_per_hour: f64,
    pub intent_distribution: String,
    pub avg_trust_score: f64,
    pub known_peers: String,
    pub avg_payload_bytes: f64,
    pub normal_hours: String,
    pub learning_complete: i64,
    pub sample_count: i64,
    pub last_updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecurityIncidentRow {
    pub id: String,
    pub org_id: String,
    pub severity: String,
    pub attack_type: String,
    pub entry_point_entity_id: Option<String>,
    pub affected_entities: String,
    pub attack_timeline: String,
    pub mitre_ttps: String,
    pub vulnerability: Option<String>,
    pub remediation: Option<String>,
    pub status: String,
    pub detected_at: i64,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CommPolicy {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub source_type: Option<String>,
    pub dest_type: Option<String>,
    pub allowed_intents: String,
    pub max_sessions_per_hour: Option<i64>,
    pub require_clearance_match: i64,
    pub enabled: i64,
    pub priority: i64,
    pub created_at: i64,
}

// ═══════════════════════════════════════════════════════════════
//  Request Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct SignupReq {
    pub org_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SigninReq {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateEntityReq {
    pub name: String,
    pub entity_type: String,
    pub department: Option<String>,
    pub clearance_level: Option<u8>,
    pub allowed_intents: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyReq {
    pub name: String,
    pub source_type: Option<String>,
    pub dest_type: Option<String>,
    pub allowed_intents: Vec<String>,
    pub max_sessions_per_hour: Option<i64>,
    pub require_clearance_match: Option<bool>,
    pub priority: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyReq {
    pub name: Option<String>,
    pub source_type: Option<String>,
    pub dest_type: Option<String>,
    pub allowed_intents: Option<Vec<String>>,
    pub max_sessions_per_hour: Option<i64>,
    pub require_clearance_match: Option<bool>,
    pub enabled: Option<bool>,
    pub priority: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UpdateAiConfigReq {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub trust_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyKeyReq {
    pub provider: String,
    pub model: String,
    pub api_key: String,
}

// ═══════════════════════════════════════════════════════════════
//  Response Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct AuthResp {
    pub token: String,
    pub org: Organisation,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResp {
    pub active_sessions: i64,
    pub blocked_today: i64,
    pub ai_calls: i64,
    pub avg_trust: Option<f64>,
    pub entities_online: i64,
    pub threats_detected_today: i64,
    pub uptime_secs: u64,
}

// ═══════════════════════════════════════════════════════════════
//  WebSocket Event Types — 14 variants
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    Connected {
        org_id: String,
        org_name: String,
    },

    Log {
        level: String,
        message: String,
        ts: i64,
    },

    Stats {
        active_sessions: i64,
        blocked_today: i64,
        ai_calls: i64,
        avg_trust: Option<f64>,
        entities_online: i64,
        threats_detected_today: i64,
        uptime_secs: u64,
    },

    SessionNew {
        session_id: String,
        source_entity: String,
        dest_entity: String,
        intent: String,
        trust_score: u8,
        verdict: String,
        ts: i64,
    },

    SessionEnd {
        session_id: String,
        duration_secs: u64,
        bytes_tx: u64,
        bytes_rx: u64,
        close_reason: String,
        ts: i64,
    },

    SessionKilled {
        session_id: String,
        entity_id: String,
        reason: String,
        verdict: String,
        ts: i64,
    },

    Alert {
        alert_type: String,
        severity: String,
        entity_id: Option<String>,
        description: String,
        recommended_action: String,
        ts: i64,
    },

    AnomalyDetected {
        entity_id: String,
        anomaly_type: String,
        severity: String,
        description: String,
        confidence: f32,
        ts: i64,
    },

    EntityQuarantined {
        entity_id: String,
        reason: String,
        active_sessions_killed: u32,
        ts: i64,
    },

    ThreatIncident {
        incident_id: String,
        severity: String,
        attack_type: String,
        entities_affected: u32,
        summary: String,
        ts: i64,
    },

    VulnerabilityFound {
        entity_id: String,
        cve: Option<String>,
        description: String,
        severity: String,
        remediation_available: bool,
        ts: i64,
    },

    PacketFlow {
        direction: String,
        bytes: u64,
        intent: String,
        trust: u8,
        ts: i64,
    },
}
