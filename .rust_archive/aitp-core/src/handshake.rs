//! Handshake state machine for AITP session establishment.
//!
//! Implements the 7-step handshake protocol:
//! ```text
//! INIT → HELLO_SENT → IDENTITY_EXCHANGED → INTENT_DECLARED
//!      → TRUST_EVALUATING → SESSION_ACTIVE → CLOSED / REVOKED
//! ```
//!
//! Each state transition has configurable timeouts (default 2s) and
//! retries (max 3 for HELLO). All transitions are logged as structured JSON.

use crate::header::IntentCode;
use std::time::{Duration, Instant};
use thiserror::Error;

// ────────────────────────── Configuration ──────────────────────────

/// Configuration for the handshake state machine.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Timeout per handshake phase.
    pub phase_timeout: Duration,
    /// Maximum retries for the HELLO message.
    pub max_hello_retries: u32,
    /// Maximum retries for other phases.
    pub max_retries: u32,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            phase_timeout: Duration::from_secs(2),
            max_hello_retries: 3,
            max_retries: 2,
        }
    }
}

// ────────────────────────── Errors ──────────────────────────

/// Errors during the handshake process.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// Handshake phase timed out.
    #[error("handshake timeout in state {state:?} after {elapsed:?}")]
    Timeout {
        state: HandshakeState,
        elapsed: Duration,
    },

    /// Maximum retries exceeded.
    #[error("max retries ({max}) exceeded in state {state:?}")]
    MaxRetriesExceeded { state: HandshakeState, max: u32 },

    /// Invalid state transition attempted.
    #[error("invalid transition from {from:?} on message {message:?}")]
    InvalidTransition {
        from: HandshakeState,
        message: HandshakeMessageKind,
    },

    /// Trust evaluation denied the connection.
    #[error("trust evaluation denied: score {score}, reason: {reason}")]
    TrustDenied { score: u8, reason: String },

    /// Session was revoked during handshake.
    #[error("session revoked during handshake")]
    Revoked,

    /// Peer sent an unexpected message.
    #[error("unexpected message {received:?} in state {state:?}")]
    UnexpectedMessage {
        state: HandshakeState,
        received: HandshakeMessageKind,
    },
}

// ────────────────────────── Handshake State ──────────────────────────

/// The current state of the handshake state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeState {
    /// Initial state — no messages sent.
    Init,
    /// HELLO sent, waiting for identity exchange.
    HelloSent,
    /// Identity exchange received, waiting for intent declaration.
    IdentityExchanged,
    /// Intent declared, waiting for trust evaluation.
    IntentDeclared,
    /// Trust evaluation in progress.
    TrustEvaluating,
    /// Session is active and data can flow.
    SessionActive,
    /// Session closed gracefully.
    Closed,
    /// Session revoked (immediate termination).
    Revoked,
}

impl HandshakeState {
    /// Whether this is a terminal state (Closed or Revoked).
    pub fn is_terminal(&self) -> bool {
        matches!(self, HandshakeState::Closed | HandshakeState::Revoked)
    }

    /// Whether data transfer is allowed in this state.
    pub fn can_transfer_data(&self) -> bool {
        matches!(self, HandshakeState::SessionActive)
    }
}

// ────────────────────────── Handshake Messages ──────────────────────────

/// The kind of handshake message (used for state transitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeMessageKind {
    /// Version negotiation + source identity.
    Hello,
    /// Destination identity + challenge nonce.
    IdentityExchange,
    /// Intent code + permit request.
    IntentDeclare,
    /// Trust evaluation result (internal).
    TrustEval,
    /// Permit token + trust score + constraints.
    SessionGrant,
    /// Encrypted payload data.
    Data,
    /// Immediate session termination.
    Revoke,
}

/// A handshake message with associated data.
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    /// The kind of message.
    pub kind: HandshakeMessageKind,
    /// Source entity ID.
    pub source_id: [u8; 32],
    /// Destination entity ID (may be zeros for HELLO).
    pub dest_id: [u8; 32],
    /// Session ID.
    pub session_id: u64,
    /// Intent code (relevant for IntentDeclare).
    pub intent: IntentCode,
    /// Trust score (relevant for TrustEval and SessionGrant).
    pub trust_score: u8,
    /// Challenge nonce (relevant for IdentityExchange).
    pub challenge_nonce: Option<[u8; 12]>,
    /// Optional payload (e.g., permit token bytes).
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    /// Serialize the handshake message to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100 + self.payload.len());
        buf.push(match self.kind {
            HandshakeMessageKind::Hello => 1,
            HandshakeMessageKind::IdentityExchange => 2,
            HandshakeMessageKind::IntentDeclare => 3,
            HandshakeMessageKind::TrustEval => 4,
            HandshakeMessageKind::SessionGrant => 5,
            HandshakeMessageKind::Data => 6,
            HandshakeMessageKind::Revoke => 7,
        });
        buf.extend_from_slice(&self.source_id);
        buf.extend_from_slice(&self.dest_id);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&(self.intent as u16).to_be_bytes());
        buf.push(self.trust_score);
        buf.push(if self.challenge_nonce.is_some() { 1 } else { 0 });
        if let Some(nonce) = self.challenge_nonce {
            buf.extend_from_slice(&nonce);
        }
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize a handshake message from bytes.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 86 {
            return None;
        }
        let kind = match buf[0] {
            1 => HandshakeMessageKind::Hello,
            2 => HandshakeMessageKind::IdentityExchange,
            3 => HandshakeMessageKind::IntentDeclare,
            4 => HandshakeMessageKind::TrustEval,
            5 => HandshakeMessageKind::SessionGrant,
            6 => HandshakeMessageKind::Data,
            7 => HandshakeMessageKind::Revoke,
            _ => return None,
        };
        let mut source_id = [0u8; 32];
        source_id.copy_from_slice(&buf[1..33]);
        let mut dest_id = [0u8; 32];
        dest_id.copy_from_slice(&buf[33..65]);
        let session_id = u64::from_be_bytes(buf[65..73].try_into().ok()?);
        let intent = IntentCode::from_u16(u16::from_be_bytes(buf[73..75].try_into().ok()?));
        let trust_score = buf[75];
        let has_nonce = buf[76] != 0;
        let mut offset = 77;
        let challenge_nonce = if has_nonce {
            if buf.len() < offset + 12 {
                return None;
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&buf[offset..offset + 12]);
            offset += 12;
            Some(nonce)
        } else {
            None
        };
        if buf.len() < offset + 4 {
            return None;
        }
        let payload_len = u32::from_be_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        if buf.len() < offset + payload_len {
            return None;
        }
        let payload = buf[offset..offset + payload_len].to_vec();

        Some(Self {
            kind,
            source_id,
            dest_id,
            session_id,
            intent,
            trust_score,
            challenge_nonce,
            payload,
        })
    }
}

// ────────────────────────── State Machine ──────────────────────────

/// The handshake state machine.
///
/// Manages the lifecycle of an AITP session from INIT through
/// SESSION_ACTIVE, CLOSED, or REVOKED. Each transition is validated
/// and logged.
#[derive(Debug)]
pub struct HandshakeMachine {
    /// Current state.
    state: HandshakeState,
    /// Configuration.
    config: HandshakeConfig,
    /// Session ID for this handshake.
    session_id: u64,
    /// When the current state was entered.
    state_entered_at: Instant,
    /// Retry count for the current state.
    retries: u32,
    /// Whether we are the initiator (client) or responder (server).
    _is_initiator: bool,
}

impl HandshakeMachine {
    /// Create a new handshake state machine.
    ///
    /// # Arguments
    ///
    /// * `session_id` — The session ID for this handshake.
    /// * `is_initiator` — `true` if this node is initiating the connection.
    /// * `config` — Handshake configuration.
    pub fn new(session_id: u64, is_initiator: bool, config: HandshakeConfig) -> Self {
        tracing::info!(
            session_id = format!("{:#018x}", session_id),
            is_initiator,
            state = ?HandshakeState::Init,
            "Handshake state machine created"
        );

        Self {
            state: HandshakeState::Init,
            config,
            session_id,
            state_entered_at: Instant::now(),
            retries: 0,
            _is_initiator: is_initiator,
        }
    }

    /// Get the current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Get the session ID.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Check if the current state has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.state_entered_at.elapsed() > self.config.phase_timeout
    }

    /// Get the elapsed time in the current state.
    pub fn elapsed_in_state(&self) -> Duration {
        self.state_entered_at.elapsed()
    }

    /// Transition the state machine based on a received message.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] if the transition is invalid, timed out,
    /// or the maximum retries have been exceeded.
    pub fn on_message(&mut self, msg: &HandshakeMessage) -> Result<HandshakeState, HandshakeError> {
        // Check timeout first
        if self.is_timed_out() && !self.state.is_terminal() {
            return Err(HandshakeError::Timeout {
                state: self.state,
                elapsed: self.elapsed_in_state(),
            });
        }

        // Revoke is always valid (except in terminal states)
        if msg.kind == HandshakeMessageKind::Revoke && !self.state.is_terminal() {
            return self.transition_to(HandshakeState::Revoked);
        }

        // Validate and execute state transition
        let next_state = match (self.state, msg.kind) {
            // Initiator path
            (HandshakeState::Init, HandshakeMessageKind::Hello) => HandshakeState::HelloSent,
            (HandshakeState::HelloSent, HandshakeMessageKind::IdentityExchange) => {
                HandshakeState::IdentityExchanged
            }
            (HandshakeState::IdentityExchanged, HandshakeMessageKind::IntentDeclare) => {
                HandshakeState::IntentDeclared
            }

            // Responder path
            (HandshakeState::Init, HandshakeMessageKind::IdentityExchange) => {
                // Responder receives Hello and sends IdentityExchange
                HandshakeState::IdentityExchanged
            }

            // Shared path
            (HandshakeState::IntentDeclared, HandshakeMessageKind::TrustEval) => {
                HandshakeState::TrustEvaluating
            }
            (HandshakeState::TrustEvaluating, HandshakeMessageKind::SessionGrant) => {
                HandshakeState::SessionActive
            }
            (HandshakeState::SessionActive, HandshakeMessageKind::Data) => {
                // Data messages don't change state
                HandshakeState::SessionActive
            }

            // Close
            (HandshakeState::SessionActive, HandshakeMessageKind::Revoke) => {
                HandshakeState::Revoked
            }

            // Invalid transition
            (state, message) => {
                return Err(HandshakeError::InvalidTransition {
                    from: state,
                    message,
                });
            }
        };

        self.transition_to(next_state)
    }

    /// Attempt a retry in the current state.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError::MaxRetriesExceeded`] if retries are exhausted.
    pub fn retry(&mut self) -> Result<(), HandshakeError> {
        let max = if self.state == HandshakeState::HelloSent {
            self.config.max_hello_retries
        } else {
            self.config.max_retries
        };

        self.retries += 1;
        if self.retries > max {
            return Err(HandshakeError::MaxRetriesExceeded {
                state: self.state,
                max,
            });
        }

        tracing::debug!(
            session_id = format!("{:#018x}", self.session_id),
            state = ?self.state,
            retry = self.retries,
            max_retries = max,
            "Handshake retry"
        );

        // Reset the state timer for the retry
        self.state_entered_at = Instant::now();
        Ok(())
    }

    /// Force close the handshake (graceful).
    pub fn close(&mut self) -> HandshakeState {
        let _ = self.transition_to(HandshakeState::Closed);
        self.state
    }

    /// Force revoke the handshake (immediate).
    pub fn revoke(&mut self) -> HandshakeState {
        let _ = self.transition_to(HandshakeState::Revoked);
        self.state
    }

    /// Internal: perform a state transition with logging.
    fn transition_to(&mut self, next: HandshakeState) -> Result<HandshakeState, HandshakeError> {
        let prev = self.state;
        self.state = next;
        self.retries = 0;
        self.state_entered_at = Instant::now();

        tracing::info!(
            session_id = format!("{:#018x}", self.session_id),
            from = ?prev,
            to = ?next,
            "Handshake state transition"
        );

        Ok(next)
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(kind: HandshakeMessageKind) -> HandshakeMessage {
        HandshakeMessage {
            kind,
            source_id: [0u8; 32],
            dest_id: [0u8; 32],
            session_id: 0x1234,
            intent: IntentCode::ModelInference,
            trust_score: 200,
            challenge_nonce: None,
            payload: vec![],
        }
    }

    #[test]
    fn test_full_handshake_flow() {
        let config = HandshakeConfig::default();
        let mut machine = HandshakeMachine::new(0x1234, true, config);

        assert_eq!(machine.state(), HandshakeState::Init);

        // INIT → HelloSent
        machine
            .on_message(&msg(HandshakeMessageKind::Hello))
            .unwrap();
        assert_eq!(machine.state(), HandshakeState::HelloSent);

        // HelloSent → IdentityExchanged
        machine
            .on_message(&msg(HandshakeMessageKind::IdentityExchange))
            .unwrap();
        assert_eq!(machine.state(), HandshakeState::IdentityExchanged);

        // IdentityExchanged → IntentDeclared
        machine
            .on_message(&msg(HandshakeMessageKind::IntentDeclare))
            .unwrap();
        assert_eq!(machine.state(), HandshakeState::IntentDeclared);

        // IntentDeclared → TrustEvaluating
        machine
            .on_message(&msg(HandshakeMessageKind::TrustEval))
            .unwrap();
        assert_eq!(machine.state(), HandshakeState::TrustEvaluating);

        // TrustEvaluating → SessionActive
        machine
            .on_message(&msg(HandshakeMessageKind::SessionGrant))
            .unwrap();
        assert_eq!(machine.state(), HandshakeState::SessionActive);

        assert!(machine.state().can_transfer_data());
    }

    #[test]
    fn test_invalid_transition() {
        let mut machine = HandshakeMachine::new(0x5678, true, HandshakeConfig::default());

        // Can't send Data from Init
        let result = machine.on_message(&msg(HandshakeMessageKind::Data));
        assert!(matches!(
            result,
            Err(HandshakeError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_revoke_from_any_state() {
        let mut machine = HandshakeMachine::new(0x9ABC, true, HandshakeConfig::default());

        // Advance to HelloSent
        machine
            .on_message(&msg(HandshakeMessageKind::Hello))
            .unwrap();

        // Revoke should work from any non-terminal state
        machine
            .on_message(&msg(HandshakeMessageKind::Revoke))
            .unwrap();
        assert_eq!(machine.state(), HandshakeState::Revoked);
        assert!(machine.state().is_terminal());
    }

    #[test]
    fn test_retry_logic() {
        let mut machine = HandshakeMachine::new(0xDEF0, true, HandshakeConfig::default());
        machine
            .on_message(&msg(HandshakeMessageKind::Hello))
            .unwrap();

        // Should allow up to max_hello_retries (3)
        machine.retry().unwrap();
        machine.retry().unwrap();
        machine.retry().unwrap();

        // 4th retry should fail
        let result = machine.retry();
        assert!(matches!(
            result,
            Err(HandshakeError::MaxRetriesExceeded { .. })
        ));
    }

    #[test]
    fn test_timeout_detection() {
        let config = HandshakeConfig {
            phase_timeout: Duration::from_millis(1), // Very short timeout
            ..HandshakeConfig::default()
        };
        let mut machine = HandshakeMachine::new(0x1111, true, config);
        machine
            .on_message(&msg(HandshakeMessageKind::Hello))
            .unwrap();

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        let result = machine.on_message(&msg(HandshakeMessageKind::IdentityExchange));
        assert!(matches!(result, Err(HandshakeError::Timeout { .. })));
    }

    #[test]
    fn test_close() {
        let mut machine = HandshakeMachine::new(0x2222, true, HandshakeConfig::default());
        machine.close();
        assert_eq!(machine.state(), HandshakeState::Closed);
        assert!(machine.state().is_terminal());
    }

    #[test]
    fn test_data_in_active_state() {
        let mut machine = HandshakeMachine::new(0x3333, true, HandshakeConfig::default());

        // Run through full handshake
        machine
            .on_message(&msg(HandshakeMessageKind::Hello))
            .unwrap();
        machine
            .on_message(&msg(HandshakeMessageKind::IdentityExchange))
            .unwrap();
        machine
            .on_message(&msg(HandshakeMessageKind::IntentDeclare))
            .unwrap();
        machine
            .on_message(&msg(HandshakeMessageKind::TrustEval))
            .unwrap();
        machine
            .on_message(&msg(HandshakeMessageKind::SessionGrant))
            .unwrap();

        // Data messages should keep us in SessionActive
        machine
            .on_message(&msg(HandshakeMessageKind::Data))
            .unwrap();
        assert_eq!(machine.state(), HandshakeState::SessionActive);
    }
}
