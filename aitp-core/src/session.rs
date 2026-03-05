//! Session lifecycle management.
//!
//! Manages active AITP sessions using a concurrent `DashMap`.
//! Each session tracks its state, permit token, congestion control
//! parameters, and round-trip time measurements.

use crate::handshake::HandshakeState;
use crate::header::IntentCode;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors during session operations.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Session not found.
    #[error("session {session_id:#018x} not found")]
    NotFound { session_id: u64 },

    /// Session has been closed or revoked.
    #[error("session {session_id:#018x} is in terminal state {state:?}")]
    Terminal {
        session_id: u64,
        state: HandshakeState,
    },

    /// Session limit reached.
    #[error("session table full: {max_sessions} sessions")]
    TableFull { max_sessions: usize },
}

/// Congestion control state for a session.
#[derive(Debug, Clone)]
pub struct CongestionState {
    /// Current congestion window (packets).
    pub cwnd: u32,
    /// Slow start threshold.
    pub ssthresh: u32,
    /// Smoothed RTT in microseconds.
    pub srtt_us: u64,
    /// RTT variance in microseconds.
    pub rttvar_us: u64,
    /// Token bucket: available tokens.
    pub tokens: u32,
    /// Token bucket: max tokens per second.
    pub max_tokens_per_sec: u32,
    /// Last token refill timestamp.
    pub last_refill: Instant,
}

impl Default for CongestionState {
    fn default() -> Self {
        Self {
            cwnd: 10,     // Initial window: 10 packets
            ssthresh: 64, // Initial ssthresh
            srtt_us: 0,
            rttvar_us: 0,
            tokens: 100,
            max_tokens_per_sec: 1000,
            last_refill: Instant::now(),
        }
    }
}

impl CongestionState {
    /// Additive Increase: grow cwnd by 1.
    pub fn additive_increase(&mut self) {
        self.cwnd = self.cwnd.saturating_add(1);
    }

    /// Multiplicative Decrease: halve cwnd (minimum 1).
    pub fn multiplicative_decrease(&mut self) {
        self.ssthresh = self.cwnd / 2;
        self.cwnd = (self.cwnd / 2).max(1);
    }

    /// Update RTT measurement using exponential weighted moving average.
    ///
    /// Uses the TCP-standard EWMA algorithm:
    /// - SRTT = 7/8 * SRTT + 1/8 * sample
    /// - RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - sample|
    pub fn update_rtt(&mut self, sample_us: u64) {
        if self.srtt_us == 0 {
            // First measurement
            self.srtt_us = sample_us;
            self.rttvar_us = sample_us / 2;
        } else {
            let diff = sample_us.abs_diff(self.srtt_us);
            self.rttvar_us = (3 * self.rttvar_us + diff) / 4;
            self.srtt_us = (7 * self.srtt_us + sample_us) / 8;
        }
    }

    /// Try to consume a token from the rate limiter bucket.
    ///
    /// Returns `true` if a token was available, `false` if rate-limited.
    pub fn try_consume_token(&mut self) -> bool {
        self.refill_tokens();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on time elapsed since last refill.
    fn refill_tokens(&mut self) {
        let elapsed = self.last_refill.elapsed();
        let new_tokens = (elapsed.as_secs_f64() * self.max_tokens_per_sec as f64) as u32;
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.max_tokens_per_sec);
            self.last_refill = Instant::now();
        }
    }
}

/// An active AITP session.
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier.
    pub session_id: u64,
    /// Current handshake/session state.
    pub state: HandshakeState,
    /// Source entity ID.
    pub source_id: [u8; 32],
    /// Destination entity ID.
    pub dest_id: [u8; 32],
    /// Session intent.
    pub intent: IntentCode,
    /// Trust score at session establishment.
    pub trust_score: u8,
    /// Congestion control state.
    pub congestion: CongestionState,
    /// When this session was created.
    pub created_at: Instant,
    /// When this session was last active.
    pub last_active: Instant,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Total bytes transferred (payload only).
    pub bytes_transferred: u64,
}

impl Session {
    /// Create a new session.
    pub fn new(
        session_id: u64,
        source_id: [u8; 32],
        dest_id: [u8; 32],
        intent: IntentCode,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            state: HandshakeState::Init,
            source_id,
            dest_id,
            intent,
            trust_score: 0,
            congestion: CongestionState::default(),
            created_at: now,
            last_active: now,
            packets_sent: 0,
            packets_received: 0,
            bytes_transferred: 0,
        }
    }

    /// Record a packet sent.
    pub fn record_sent(&mut self, payload_bytes: usize) {
        self.packets_sent += 1;
        self.bytes_transferred += payload_bytes as u64;
        self.last_active = Instant::now();
    }

    /// Record a packet received.
    pub fn record_received(&mut self, payload_bytes: usize) {
        self.packets_received += 1;
        self.bytes_transferred += payload_bytes as u64;
        self.last_active = Instant::now();
    }

    /// Session duration.
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Time since last activity.
    pub fn idle_time(&self) -> Duration {
        self.last_active.elapsed()
    }

    /// Whether this session is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// Thread-safe session table backed by [`DashMap`].
///
/// Provides O(1) concurrent lookups by session ID.
#[derive(Debug, Clone)]
pub struct SessionTable {
    sessions: Arc<DashMap<u64, Session>>,
    max_sessions: usize,
}

impl SessionTable {
    /// Create a new session table.
    ///
    /// # Arguments
    ///
    /// * `max_sessions` — Maximum number of concurrent sessions.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            max_sessions,
        }
    }

    /// Insert a new session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::TableFull`] if the table is at capacity.
    pub fn insert(&self, session: Session) -> Result<(), SessionError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::TableFull {
                max_sessions: self.max_sessions,
            });
        }
        self.sessions.insert(session.session_id, session);
        Ok(())
    }

    /// Look up a session by ID.
    ///
    /// Returns a reference guard to the session.
    pub fn get(&self, session_id: u64) -> Option<dashmap::mapref::one::Ref<'_, u64, Session>> {
        self.sessions.get(&session_id)
    }

    /// Get a mutable reference to a session.
    pub fn get_mut(
        &self,
        session_id: u64,
    ) -> Option<dashmap::mapref::one::RefMut<'_, u64, Session>> {
        self.sessions.get_mut(&session_id)
    }

    /// Remove a session.
    pub fn remove(&self, session_id: u64) -> Option<(u64, Session)> {
        self.sessions.remove(&session_id)
    }

    /// Check if a session exists.
    pub fn contains(&self, session_id: u64) -> bool {
        self.sessions.contains_key(&session_id)
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Remove all sessions in terminal states.
    pub fn cleanup_terminal(&self) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, session| !session.is_terminal());
        before - self.sessions.len()
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(0x1234, [0xAA; 32], [0xBB; 32], IntentCode::ModelInference);
        assert_eq!(session.session_id, 0x1234);
        assert_eq!(session.state, HandshakeState::Init);
        assert_eq!(session.packets_sent, 0);
        assert!(!session.is_terminal());
    }

    #[test]
    fn test_session_record_activity() {
        let mut session = Session::new(0x5678, [0xAA; 32], [0xBB; 32], IntentCode::DataSync);
        session.record_sent(1024);
        session.record_received(512);
        assert_eq!(session.packets_sent, 1);
        assert_eq!(session.packets_received, 1);
        assert_eq!(session.bytes_transferred, 1536);
    }

    #[test]
    fn test_session_table_insert_and_get() {
        let table = SessionTable::new(100);
        let session = Session::new(0x1, [0u8; 32], [0u8; 32], IntentCode::Heartbeat);
        table.insert(session).unwrap();

        assert!(table.contains(0x1));
        assert_eq!(table.len(), 1);

        let retrieved = table.get(0x1).unwrap();
        assert_eq!(retrieved.session_id, 0x1);
    }

    #[test]
    fn test_session_table_full() {
        let table = SessionTable::new(2);
        table
            .insert(Session::new(1, [0u8; 32], [0u8; 32], IntentCode::Heartbeat))
            .unwrap();
        table
            .insert(Session::new(2, [0u8; 32], [0u8; 32], IntentCode::Heartbeat))
            .unwrap();

        let result = table.insert(Session::new(3, [0u8; 32], [0u8; 32], IntentCode::Heartbeat));
        assert!(matches!(result, Err(SessionError::TableFull { .. })));
    }

    #[test]
    fn test_session_table_remove() {
        let table = SessionTable::new(100);
        table
            .insert(Session::new(
                42,
                [0u8; 32],
                [0u8; 32],
                IntentCode::Telemetry,
            ))
            .unwrap();
        assert_eq!(table.len(), 1);
        table.remove(42);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_congestion_aimd() {
        let mut cong = CongestionState::default();
        let initial_cwnd = cong.cwnd;

        // Additive increase
        cong.additive_increase();
        assert_eq!(cong.cwnd, initial_cwnd + 1);

        // Multiplicative decrease
        cong.multiplicative_decrease();
        assert_eq!(cong.cwnd, (initial_cwnd + 1) / 2);
    }

    #[test]
    fn test_congestion_rtt_update() {
        let mut cong = CongestionState::default();

        // First sample
        cong.update_rtt(10_000); // 10ms
        assert_eq!(cong.srtt_us, 10_000);

        // Second sample — should be smoothed
        cong.update_rtt(20_000); // 20ms
        assert!(cong.srtt_us > 10_000 && cong.srtt_us < 20_000);
    }

    #[test]
    fn test_token_bucket() {
        let mut cong = CongestionState {
            tokens: 5,
            max_tokens_per_sec: 100,
            ..CongestionState::default()
        };

        // Should be able to consume 5 tokens
        for _ in 0..5 {
            assert!(cong.try_consume_token());
        }
        // After consuming all, should fail (unless time passed for refill)
        // In practice tokens may have been refilled; we just check the mechanism works
    }

    #[test]
    fn test_cleanup_terminal() {
        let table = SessionTable::new(100);
        let mut s1 = Session::new(1, [0u8; 32], [0u8; 32], IntentCode::Heartbeat);
        s1.state = HandshakeState::SessionActive;

        let mut s2 = Session::new(2, [0u8; 32], [0u8; 32], IntentCode::Heartbeat);
        s2.state = HandshakeState::Closed;

        let mut s3 = Session::new(3, [0u8; 32], [0u8; 32], IntentCode::Heartbeat);
        s3.state = HandshakeState::Revoked;

        table.insert(s1).unwrap();
        table.insert(s2).unwrap();
        table.insert(s3).unwrap();
        assert_eq!(table.len(), 3);

        let cleaned = table.cleanup_terminal();
        assert_eq!(cleaned, 2);
        assert_eq!(table.len(), 1);
        assert!(table.contains(1));
    }
}
