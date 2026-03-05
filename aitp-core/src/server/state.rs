//! Shared server state for the TUI and alert engine.

use crate::events::EntityId;
use crate::header::IntentCode;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

// ────────────────────────── Types ──────────────────────────

/// Log entry level — drives colour in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Ok,     // green
    Info,   // cyan
    Warn,   // yellow
    Alert,  // red (bold)
    Trust,  // magenta
    Intent, // blue (intent fingerprint events)
    Sys,    // dark gray
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "[OK   ]",
            Self::Info => "[INFO ]",
            Self::Warn => "[WARN ]",
            Self::Alert => "[ALERT]",
            Self::Trust => "[TRUST]",
            Self::Intent => "[INTEN]",
            Self::Sys => "[SYS  ]",
        }
    }
}

/// A single structured log entry in the rolling log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            message: message.into(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_meta(mut self, key: &str, value: impl ToString) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Security alert type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertType {
    AnonymousConnection,
    SynFlood,
    ReplayAttack,
    IntentMismatch,
    SybilSuspect,
    ScoreCollapse,
    PromptInjection,
    HandshakeTimeout,
    PermitExpired,
    MassRevocation,
}

impl AlertType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnonymousConnection => "ANONYMOUS CONNECTION ATTEMPT",
            Self::SynFlood => "SYN FLOOD / DDOS DETECTED",
            Self::ReplayAttack => "REPLAY ATTACK — NONCE REUSE",
            Self::IntentMismatch => "INTENT MISMATCH — BEHAVIORAL ANOMALY",
            Self::SybilSuspect => "SYBIL SUSPECT — IDENTITY FLOOD",
            Self::ScoreCollapse => "TRUST SCORE COLLAPSE",
            Self::PromptInjection => "GEMINI PROMPT INJECTION BLOCKED",
            Self::HandshakeTimeout => "HANDSHAKE TIMEOUT",
            Self::PermitExpired => "EXPIRED PERMIT USED",
            Self::MassRevocation => "MASS SESSION REVOCATION",
        }
    }
}

/// A security alert entry shown in the red alert box.
#[derive(Debug, Clone)]
pub struct AlertEntry {
    pub timestamp: DateTime<Utc>,
    pub alert_type: AlertType,
    pub source_ip: IpAddr,
    pub detail: String,
    /// How many times this alert type has fired today.
    pub occurrence_count: u32,
}

impl AlertEntry {
    pub fn new(alert_type: AlertType, source_ip: IpAddr, detail: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            alert_type,
            source_ip,
            detail: detail.into(),
            occurrence_count: 1,
        }
    }
}

/// A connected client shown in the left pane.
#[derive(Debug, Clone)]
pub struct ConnectedClient {
    pub session_id: u64,
    pub entity_id: EntityId,
    pub display_name: String,
    pub peer_addr: std::net::SocketAddr,
    pub trust_score: u8,
    pub intent: IntentCode,
    pub connected_at: DateTime<Utc>,
    pub packets_received: u64,
    pub bytes_received: u64,
}

impl ConnectedClient {
    pub fn trust_label(&self) -> &'static str {
        match self.trust_score {
            185..=255 => "Allow",
            128..=184 => "Monitor",
            64..=127 => "Restrict",
            _ => "Deny",
        }
    }
}

/// Atomic server-wide statistics.
#[derive(Debug, Default)]
pub struct ServerStats {
    pub total_sessions: AtomicU32,
    pub active_sessions: AtomicU32,
    pub blocked_packets: AtomicU64,
    pub alert_count: AtomicU32,
    /// Running sum for average trust (divide by active_sessions).
    pub trust_sum: AtomicU64,
}

impl ServerStats {
    pub fn avg_trust(&self) -> u8 {
        let active = self.active_sessions.load(Ordering::Relaxed);
        if active == 0 {
            return 0;
        }
        let sum = self.trust_sum.load(Ordering::Relaxed);
        (sum / active as u64).min(255) as u8
    }
}

// ────────────────────────── ServerState ──────────────────────────

/// Maximum number of log entries kept in memory.
const MAX_LOG_ENTRIES: usize = 500;
/// Maximum number of alerts retained.
const MAX_ALERTS: usize = 20;

/// Central shared state consumed by the TUI and alert engine.
#[derive(Debug)]
pub struct ServerState {
    /// Currently connected clients (session_id → client).
    pub clients: DashMap<u64, ConnectedClient>,
    /// Rolling event log (newest-last; TUI reverses for display).
    pub log: RwLock<VecDeque<LogEntry>>,
    /// Recent security alerts.
    pub alerts: RwLock<Vec<AlertEntry>>,
    /// Aggregate counters.
    pub stats: Arc<ServerStats>,
    /// Per-IP new-identity counter (for Sybil detection).
    pub ip_new_ids: DashMap<IpAddr, u32>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
            log: RwLock::new(VecDeque::with_capacity(MAX_LOG_ENTRIES + 1)),
            alerts: RwLock::new(Vec::with_capacity(MAX_ALERTS + 1)),
            stats: Arc::new(ServerStats::default()),
            ip_new_ids: DashMap::new(),
        }
    }

    /// Append a log entry to the rolling log (evicts oldest when full).
    pub fn push_log(&self, entry: LogEntry) {
        if let Ok(mut log) = self.log.write() {
            log.push_back(entry);
            if log.len() > MAX_LOG_ENTRIES {
                log.pop_front();
            }
        }
    }

    /// Append a security alert, incrementing occurrence count if same type fires again.
    pub fn push_alert(&self, alert: AlertEntry) {
        if let Ok(mut alerts) = self.alerts.write() {
            // Bump occurrence count if the same type is already present.
            if let Some(existing) = alerts.iter_mut().find(|a| a.alert_type == alert.alert_type) {
                existing.occurrence_count += 1;
                existing.timestamp = alert.timestamp;
                existing.detail = alert.detail;
            } else {
                alerts.push(alert);
                if alerts.len() > MAX_ALERTS {
                    alerts.remove(0);
                }
            }
            self.stats.alert_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Add a newly established client.
    pub fn add_client(&self, client: ConnectedClient) {
        self.stats.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.total_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats
            .trust_sum
            .fetch_add(client.trust_score as u64, Ordering::Relaxed);
        self.clients.insert(client.session_id, client);
    }

    /// Remove a client when their session ends.
    pub fn remove_client(&self, session_id: u64) {
        if let Some((_, client)) = self.clients.remove(&session_id) {
            self.stats.active_sessions.fetch_sub(1, Ordering::Relaxed);
            let score = client.trust_score as u64;
            let _ = self
                .stats
                .trust_sum
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(score))
                });
        }
    }

    /// Number of new identities seen from this IP in any tracked window.
    pub fn count_new_ids_from_ip(&self, ip: IpAddr) -> u32 {
        self.ip_new_ids.get(&ip).map(|v| *v).unwrap_or(0)
    }

    /// Record a new identity from this IP (for Sybil detection).
    pub fn record_new_id_from_ip(&self, ip: IpAddr) {
        *self.ip_new_ids.entry(ip).or_insert(0) += 1;
    }
}
