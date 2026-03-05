//! Permit token generation and validation.
//!
//! A permit token authorizes a session between two entities for a specific
//! intent. Tokens are signed by the issuer (typically the control plane)
//! and have a bounded TTL for automatic expiry.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ────────────────────────── Errors ──────────────────────────

/// Errors during permit token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    /// Token signature is invalid.
    #[error("invalid token signature: {0}")]
    InvalidSignature(String),

    /// Token has expired.
    #[error("token expired: issued at {issued_at}, TTL {ttl_secs}s, current time {now}")]
    Expired {
        issued_at: u64,
        ttl_secs: u32,
        now: u64,
    },

    /// Invalid public key provided for verification.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Token data is malformed.
    #[error("malformed token data: {0}")]
    Malformed(String),
}

// ────────────────────────── Session Constraints ──────────────────────────

/// Constraints applied to an authorized session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConstraints {
    /// Maximum payload size per packet (bytes).
    pub max_payload_bytes: u32,
    /// Rate limit: max packets per second.
    pub rate_limit_pps: u32,
    /// Allowed intent codes. Empty means all intents allowed.
    pub allowed_intents: Vec<u16>,
    /// Whether enhanced monitoring is enabled.
    pub enhanced_monitoring: bool,
}

impl Default for SessionConstraints {
    fn default() -> Self {
        Self {
            max_payload_bytes: 65535,
            rate_limit_pps: 1000,
            allowed_intents: Vec::new(),
            enhanced_monitoring: false,
        }
    }
}

// ────────────────────────── Permit Token ──────────────────────────

/// A permit token authorizing a specific session.
///
/// Permits are created by the session acceptor or control plane,
/// signed with the issuer's private key, and validated by the recipient.
///
/// # Serialization
///
/// The token is serialized to a deterministic byte layout for signing.
/// The signature covers all fields except the signature itself.
#[derive(Debug, Clone)]
pub struct PermitToken {
    /// Unique session identifier.
    pub session_id: u64,
    /// Source entity ID (SHA-256 of public key).
    pub source_id: [u8; 32],
    /// Destination entity ID.
    pub dest_id: [u8; 32],
    /// Authorized intent code.
    pub intent: u16,
    /// Trust score at the time of issuance.
    pub trust_score: u8,
    /// Session constraints.
    pub constraints: SessionConstraints,
    /// Unix timestamp (seconds) when this token was issued.
    pub issued_at: u64,
    /// Time-to-live in seconds.
    pub ttl_secs: u32,
    /// Ed25519 signature by the issuer.
    pub signature: [u8; 64],
}

impl PermitToken {
    /// Create a new unsigned permit token.
    ///
    /// The caller must sign it via [`sign`](PermitToken::sign) before use.
    pub fn new(
        session_id: u64,
        source_id: [u8; 32],
        dest_id: [u8; 32],
        intent: u16,
        trust_score: u8,
        constraints: SessionConstraints,
        ttl_secs: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            session_id,
            source_id,
            dest_id,
            intent,
            trust_score,
            constraints,
            issued_at: now,
            ttl_secs,
            signature: [0u8; 64],
        }
    }

    /// Serialize the token fields (excluding signature) for signing.
    ///
    /// # Layout
    ///
    /// ```text
    /// session_id (8) + source_id (32) + dest_id (32) + intent (2)
    /// + trust_score (1) + issued_at (8) + ttl_secs (4) = 87 bytes
    /// ```
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(87);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.source_id);
        buf.extend_from_slice(&self.dest_id);
        buf.extend_from_slice(&self.intent.to_be_bytes());
        buf.push(self.trust_score);
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.ttl_secs.to_be_bytes());
        buf
    }

    /// Sign this token with the issuer's private key.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let msg = self.signable_bytes();
        let sig = signing_key.sign(&msg);
        self.signature = sig.to_bytes();
    }

    /// Verify the token signature against the issuer's public key.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidSignature`] on failure.
    pub fn verify_signature(&self, issuer_pubkey: &[u8; 32]) -> Result<(), TokenError> {
        let verifying_key = VerifyingKey::from_bytes(issuer_pubkey)
            .map_err(|e| TokenError::InvalidPublicKey(e.to_string()))?;

        let sig = Signature::from_bytes(&self.signature);
        let msg = self.signable_bytes();

        verifying_key
            .verify(&msg, &sig)
            .map_err(|e| TokenError::InvalidSignature(e.to_string()))
    }

    /// Check whether this token has expired.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Expired`] if the current time exceeds
    /// `issued_at + ttl_secs`.
    pub fn check_expiry(&self) -> Result<(), TokenError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = self.issued_at.saturating_add(self.ttl_secs as u64);

        if now > expires_at {
            Err(TokenError::Expired {
                issued_at: self.issued_at,
                ttl_secs: self.ttl_secs,
                now,
            })
        } else {
            Ok(())
        }
    }

    /// Validate the token: check signature and expiry.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered (signature or expiry).
    pub fn validate(&self, issuer_pubkey: &[u8; 32]) -> Result<(), TokenError> {
        self.verify_signature(issuer_pubkey)?;
        self.check_expiry()?;
        Ok(())
    }

    /// Remaining time-to-live in seconds. Returns 0 if expired.
    pub fn remaining_ttl_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at = self.issued_at.saturating_add(self.ttl_secs as u64);
        expires_at.saturating_sub(now)
    }

    /// Serialize the token to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.signable_bytes();
        let constraints_json = serde_json::to_vec(&self.constraints).unwrap_or_default();
        buf.extend_from_slice(&(constraints_json.len() as u32).to_be_bytes());
        buf.extend_from_slice(&constraints_json);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize a token from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, TokenError> {
        if buf.len() < 87 + 4 + 64 {
            return Err(TokenError::Malformed("buffer too short".into()));
        }
        let session_id = u64::from_be_bytes(buf[0..8].try_into().unwrap());
        let mut source_id = [0u8; 32];
        source_id.copy_from_slice(&buf[8..40]);
        let mut dest_id = [0u8; 32];
        dest_id.copy_from_slice(&buf[40..72]);
        let intent = u16::from_be_bytes(buf[72..74].try_into().unwrap());
        let trust_score = buf[74];
        let issued_at = u64::from_be_bytes(buf[75..83].try_into().unwrap());
        let ttl_secs = u32::from_be_bytes(buf[83..87].try_into().unwrap());

        let constraints_len = u32::from_be_bytes(buf[87..91].try_into().unwrap()) as usize;
        if buf.len() < 91 + constraints_len + 64 {
            return Err(TokenError::Malformed(
                "buffer too short for constraints".into(),
            ));
        }
        let constraints: SessionConstraints =
            serde_json::from_slice(&buf[91..91 + constraints_len])
                .map_err(|e| TokenError::Malformed(e.to_string()))?;

        let sig_start = 91 + constraints_len;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[sig_start..sig_start + 64]);

        Ok(Self {
            session_id,
            source_id,
            dest_id,
            intent,
            trust_score,
            constraints,
            issued_at,
            ttl_secs,
            signature,
        })
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn test_create_and_sign_token() {
        let key = test_signing_key();
        let mut token = PermitToken::new(
            1234,
            [0xAA; 32],
            [0xBB; 32],
            0x0001,
            180,
            SessionConstraints::default(),
            300,
        );
        token.sign(&key);
        assert_ne!(token.signature, [0u8; 64]);
    }

    #[test]
    fn test_verify_valid_signature() {
        let key = test_signing_key();
        let pubkey = *key.verifying_key().as_bytes();

        let mut token = PermitToken::new(
            5678,
            [0xCC; 32],
            [0xDD; 32],
            0x0002,
            200,
            SessionConstraints::default(),
            600,
        );
        token.sign(&key);
        token.verify_signature(&pubkey).expect("Should verify OK");
    }

    #[test]
    fn test_tampered_token_fails() {
        let key = test_signing_key();
        let pubkey = *key.verifying_key().as_bytes();

        let mut token = PermitToken::new(
            1,
            [0x11; 32],
            [0x22; 32],
            0x0003,
            100,
            SessionConstraints::default(),
            300,
        );
        token.sign(&key);

        // Tamper
        token.trust_score = 255;
        assert!(token.verify_signature(&pubkey).is_err());
    }

    #[test]
    fn test_token_not_expired() {
        let token = PermitToken::new(
            1,
            [0u8; 32],
            [0u8; 32],
            0x0001,
            128,
            SessionConstraints::default(),
            3600,
        );
        token.check_expiry().expect("Token should not be expired");
    }

    #[test]
    fn test_token_expired() {
        let mut token = PermitToken::new(
            1,
            [0u8; 32],
            [0u8; 32],
            0x0001,
            128,
            SessionConstraints::default(),
            0, // TTL = 0
        );
        // Set issued_at to the past
        token.issued_at = 1_000_000;
        assert!(token.check_expiry().is_err());
    }

    #[test]
    fn test_full_validate() {
        let key = test_signing_key();
        let pubkey = *key.verifying_key().as_bytes();

        let mut token = PermitToken::new(
            42,
            [0xAA; 32],
            [0xBB; 32],
            0x00FF,
            200,
            SessionConstraints::default(),
            3600,
        );
        token.sign(&key);
        token
            .validate(&pubkey)
            .expect("Full validation should pass");
    }

    #[test]
    fn test_remaining_ttl() {
        let token = PermitToken::new(
            1,
            [0u8; 32],
            [0u8; 32],
            0x0001,
            128,
            SessionConstraints::default(),
            3600,
        );
        let remaining = token.remaining_ttl_secs();
        assert!(remaining > 3500 && remaining <= 3600);
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let token = PermitToken::new(
            999,
            [0x11; 32],
            [0x22; 32],
            0x0005,
            150,
            SessionConstraints::default(),
            600,
        );
        let b1 = token.signable_bytes();
        let b2 = token.signable_bytes();
        assert_eq!(b1, b2);
        assert_eq!(b1.len(), 87);
    }
}
