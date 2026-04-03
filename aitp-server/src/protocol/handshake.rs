use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{AitpHeader, IntentCode};
use crate::crypto::HybridKem;
use pqcrypto_mlkem::mlkem768::SecretKey as KemSk;
use x25519_dalek::{PublicKey as X25519Pk, StaticSecret as X25519Sk};

#[cfg(test)]
use super::{FLAG_ACK, FLAG_SYN};

// ────────────────────────── Handshake State Machine ──────────────────────────

/// Five-phase handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakePhase {
    /// Phase 1: Client sends SYN with identity
    AwaitingSyn,
    /// Phase 2: Server verifies identity, sends SYN-ACK challenge
    AwaitingSynAck,
    /// Phase 3: Client responds to challenge
    AwaitingChallengeResponse,
    /// Phase 4: Server evaluates trust
    AwaitingTrustEval,
    /// Phase 5: Session established or denied
    Complete,
}

/// Context for an in-progress handshake.
#[derive(Clone)]
pub struct HandshakeContext {
    pub phase: HandshakePhase,
    pub session_id: u64,
    pub source_entity_id: String,
    pub dest_entity_id: String,
    pub intent: IntentCode,
    pub challenge_nonce: Option<[u8; 12]>,
    pub trust_score: Option<u8>,
    pub verdict: Option<String>,
    pub started_at: i64,
    pub session_key: Option<[u8; 32]>,
}

/// Manages in-progress handshakes.
pub struct HandshakeManager {
    active: HashMap<u64, HandshakeContext>, // session_id → context
}

impl Default for HandshakeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeManager {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
        }
    }

    /// Begin a new handshake from a SYN packet.
    pub fn begin(&mut self, header: &AitpHeader) -> Result<&HandshakeContext, &'static str> {
        if !header.is_syn() {
            return Err("expected SYN flag for handshake initiation");
        }

        let ctx = HandshakeContext {
            phase: HandshakePhase::AwaitingSynAck,
            session_id: header.session_id,
            source_entity_id: hex::encode(header.source_id()),
            dest_entity_id: hex::encode(header.dest_id),
            intent: IntentCode::from_u16(header.intent),
            challenge_nonce: Some(header.nonce),
            trust_score: None,
            verdict: None,
            started_at: chrono::Utc::now().timestamp(),
            session_key: None,
        };

        self.active.insert(header.session_id, ctx);
        Ok(self.active.get(&header.session_id).unwrap())
    }

    /// Advance handshake after trust evaluation.
    pub fn complete_trust_eval(
        &mut self,
        session_id: u64,
        trust_score: u8,
        verdict: &str,
    ) -> Result<&HandshakeContext, &'static str> {
        let ctx = self
            .active
            .get_mut(&session_id)
            .ok_or("no active handshake for session")?;

        ctx.trust_score = Some(trust_score);
        ctx.verdict = Some(verdict.to_string());
        ctx.phase = HandshakePhase::Complete;
        Ok(ctx)
    }

    /// Process a received KEM ciphertext from an initiator to derive the session shared secret.
    #[allow(dead_code)]
    pub fn decapsulate_session_key(
        &mut self,
        session_id: u64,
        server_classical_sk: X25519Sk,
        server_pq_sk: &KemSk,
        client_classical_pk: &X25519Pk,
        pq_ciphertext: &[u8],
    ) -> Result<(), &'static str> {
        let ctx = self
            .active
            .get_mut(&session_id)
            .ok_or("no active handshake for session")?;

        let shared_secret = HybridKem::decapsulate(
            server_classical_sk,
            server_pq_sk,
            client_classical_pk,
            pq_ciphertext,
        )
        .map_err(|_| "Failed to decapsulate hybrid KEM ciphertext")?;

        ctx.session_key = Some(shared_secret.0);
        Ok(())
    }

    /// Get a handshake context.
    pub fn get(&self, session_id: u64) -> Option<&HandshakeContext> {
        self.active.get(&session_id)
    }

    /// Remove a completed or failed handshake.
    pub fn remove(&mut self, session_id: u64) -> Option<HandshakeContext> {
        self.active.remove(&session_id)
    }

    /// Number of active handshakes.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Cleanup stale handshakes older than max_age_secs.
    pub fn cleanup_stale(&mut self, max_age_secs: i64) -> usize {
        let now = chrono::Utc::now().timestamp();
        let before = self.active.len();
        self.active
            .retain(|_, ctx| now - ctx.started_at < max_age_secs);
        before - self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_begin() {
        let mut mgr = HandshakeManager::new();
        let hdr = AitpHeader {
            version: 4,
            flags: FLAG_SYN,
            intent: IntentCode::ModelInference as u16,
            session_id: 100,
            timestamp: 0,
            nonce: [0u8; 12],
            algorithm: 1,
            source_pk: vec![1u8; 32],
            dest_id: [2u8; 32],
            signature: vec![],
            payload_len: 0,
        };

        let ctx = mgr.begin(&hdr).unwrap();
        assert_eq!(ctx.phase, HandshakePhase::AwaitingSynAck);
        assert_eq!(ctx.session_id, 100);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_handshake_non_syn_fails() {
        let mut mgr = HandshakeManager::new();
        let hdr = AitpHeader {
            version: 4,
            flags: FLAG_ACK,
            intent: IntentCode::ModelInference as u16,
            session_id: 100,
            timestamp: 0,
            nonce: [0u8; 12],
            algorithm: 1,
            source_pk: vec![1u8; 32],
            dest_id: [2u8; 32],
            signature: vec![],
            payload_len: 0,
        };

        assert!(mgr.begin(&hdr).is_err());
    }

    #[test]
    fn test_handshake_complete() {
        let mut mgr = HandshakeManager::new();
        let hdr = AitpHeader {
            version: 4,
            flags: FLAG_SYN,
            intent: IntentCode::DataSync as u16,
            session_id: 200,
            timestamp: 0,
            nonce: [0; 12],
            algorithm: 1,
            source_pk: vec![1; 32],
            dest_id: [2; 32],
            signature: vec![],
            payload_len: 0,
        };

        mgr.begin(&hdr).unwrap();
        let ctx = mgr.complete_trust_eval(200, 180, "Allow").unwrap();
        assert_eq!(ctx.phase, HandshakePhase::Complete);
        assert_eq!(ctx.trust_score, Some(180));
        assert_eq!(ctx.verdict.as_deref(), Some("Allow"));
    }

    #[test]
    fn test_handshake_cleanup() {
        let mut mgr = HandshakeManager::new();
        let hdr = AitpHeader {
            version: 4,
            flags: FLAG_SYN,
            intent: IntentCode::Heartbeat as u16,
            session_id: 300,
            timestamp: 0,
            nonce: [0u8; 12],
            algorithm: 1,
            source_pk: vec![1u8; 32],
            dest_id: [2u8; 32],
            signature: vec![],
            payload_len: 0,
        };

        mgr.begin(&hdr).unwrap();
        // Should not clean up fresh handshakes
        let cleaned = mgr.cleanup_stale(60);
        assert_eq!(cleaned, 0);
        assert_eq!(mgr.active_count(), 1);
    }
}
