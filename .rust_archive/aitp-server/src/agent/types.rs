// AITP Agentic Threat Response Engine — types.rs
// All data types for the ReAct agent: actions, observations, incidents.

use serde::{Deserialize, Serialize};

// ─── Agent Actions (Tools) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum AgentAction {
    QueryAuditChain {
        entity_id: Option<String>,
        time_range_start: i64,
        time_range_end: i64,
        event_types: Vec<String>,
    },
    QueryEntityHistory {
        entity_id: String,
    },
    QuerySessionDetails {
        session_id: String,
    },
    QueryRelatedEntities {
        entity_id: String,
        time_window_secs: i64,
    },
    SearchCVE {
        service_name: String,
        version: String,
    },
    QueryMitreAttack {
        behavior_description: String,
    },
    GetNetworkTopology {},
    QuarantineEntity {
        entity_id: String,
        reason: String,
    },
    RevokeSession {
        session_id: String,
        reason: String,
    },
    BlockIP {
        ip_address: String,
        reason: String,
        duration_secs: u64,
    },
    AlertAdmin {
        message: String,
        severity: String,
    },
    GenerateIncidentReport {
        summary: String,
        attack_type: String,
        entry_point: Option<String>,
        timeline: Vec<TimelineEvent>,
        mitre_ttps: Vec<String>,
        vulnerability: Option<String>,
        remediation_runbook: Vec<String>,
        confidence: f32,
    },
}

// ─── Timeline Event ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: i64,
    pub event_type: String,
    pub entity_id: String,
    pub description: String,
    pub severity: String,
}

// ─── Agent Step (THOUGHT + ACTION + OBSERVATION) ────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStep {
    pub step_number: u32,
    pub thought: String,
    pub action: AgentAction,
    pub observation: String,
}

// ─── CVE Entry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub service: String,
    pub affected_versions: String,
    pub cvss_score: f32,
    pub description: String,
    pub patch_version: String,
    pub remediation: String,
}

// ─── MITRE TTP ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTtp {
    pub id: String,
    pub tactic: String,
    pub technique: String,
    pub description: String,
}

// ─── Security Incident (final agent output) ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIncidentReport {
    pub id: String,
    pub org_id: String,
    pub severity: String,
    pub attack_type: String,
    pub summary: String,
    pub entry_point_entity_id: Option<String>,
    pub affected_entities: Vec<String>,
    pub timeline: Vec<TimelineEvent>,
    pub mitre_ttps: Vec<MitreTtp>,
    pub vulnerability: Option<String>,
    pub data_at_risk: Vec<String>,
    pub what_attacker_did: Vec<String>,
    pub what_was_prevented: Vec<String>,
    pub remediation_runbook: Vec<String>,
    pub confidence: f32,
    pub automated_actions_taken: Vec<String>,
    pub detected_at: i64,
    pub investigation_steps: u32,
    pub investigation_log: Vec<AgentStep>,
}
