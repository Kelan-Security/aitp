//! AITP Packet Header — wire format definition and serialization.
//!
//! Defines the core AITP packet header as a `#[repr(C)]` struct for
//! deterministic byte layout. Provides zero-copy serialization and
//! deserialization for the hot path (no serde, no protobuf).
//!
//! # Wire Format (148 bytes fixed header)
//!
//! ```text
//! Offset  Size   Field
//! ------  ----   -----
//!   0       1    Version (4 bits) + Flags (4 bits)
//!   1       2    Intent Code (u16 BE)
//!   3       8    Session ID (u64 BE)
//!  11      32    Source Identity ID (SHA-256 of Ed25519 pubkey)
//!  43      32    Destination Identity ID
//!  75       1    Trust Score (u8)
//!  76       1    Reserved
//!  77       2    Payload Length (u16 BE)
//!  79       8    Timestamp (u64 BE, Unix epoch nanoseconds)
//!  87      12    Nonce (96 bits)
//!  99      64    Ed25519 Signature
//! 163    3309    ML-DSA-65 Detached Signature
//! 3472     ..    Payload (variable, `payload_len` bytes)
//! ```

use aitp_identity::identity::{AitpIdentity, HybridSignature};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_mldsa::mldsa65;
use std::fmt;
use thiserror::Error;

// ────────────────────────── Constants ──────────────────────────

/// Current AITP protocol version.
pub const AITP_VERSION: u8 = 1;

/// Size of the ML-DSA-65 (Dilithium3) signature
pub const PQ_SIG_SIZE: usize = 3309;

/// Size of the fixed header in bytes (before payload).
pub const HEADER_SIZE: usize = 163 + PQ_SIG_SIZE;

/// Maximum payload size (limited by u16 payload_len field).
pub const MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;

/// Default AITP UDP port.
pub const DEFAULT_UDP_PORT: u16 = 9999;

// ────────────────────────── Flags ──────────────────────────

/// Packet flag bits (lower 4 bits of the version/flags byte).
pub mod flags {
    /// Synchronize — initiate handshake.
    pub const SYN: u8 = 0b0001;
    /// Acknowledge — confirm handshake step.
    pub const ACK: u8 = 0b0010;
    /// Finish — graceful session close.
    pub const FIN: u8 = 0b0100;
    /// Revoke — immediate session termination.
    pub const REVOKE: u8 = 0b1000;
}

// ────────────────────────── Intent Codes ──────────────────────────

/// Semantic intent codes describing the purpose of a session.
///
/// Intent codes are embedded in every AITP packet, enabling
/// the trust engine and eBPF enforcement layer to make routing
/// and access decisions based on what the session is doing,
/// not just where it is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IntentCode {
    /// Unknown or unspecified intent.
    Unknown = 0x0000,
    /// LLM or ML model inference request.
    ModelInference = 0x0001,
    /// State synchronization between services.
    DataSync = 0x0002,
    /// Control plane signaling message.
    ControlSignal = 0x0003,
    /// Observability / telemetry data.
    Telemetry = 0x0004,
    /// Multi-agent coordination message.
    AgentCoordinate = 0x0005,
    /// File or bulk data transfer.
    FileTransfer = 0x0006,
    /// Keepalive heartbeat.
    Heartbeat = 0x00FF,
}

impl IntentCode {
    /// Convert a raw u16 to an [`IntentCode`], returning [`IntentCode::Unknown`]
    /// for unrecognized values.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0000 => IntentCode::Unknown,
            0x0001 => IntentCode::ModelInference,
            0x0002 => IntentCode::DataSync,
            0x0003 => IntentCode::ControlSignal,
            0x0004 => IntentCode::Telemetry,
            0x0005 => IntentCode::AgentCoordinate,
            0x0006 => IntentCode::FileTransfer,
            0x00FF => IntentCode::Heartbeat,
            _ => IntentCode::Unknown,
        }
    }

    /// Get the string label for this intent code (used in metrics/logs).
    pub fn as_str(&self) -> &'static str {
        match self {
            IntentCode::Unknown => "Unknown",
            IntentCode::ModelInference => "ModelInference",
            IntentCode::DataSync => "DataSync",
            IntentCode::ControlSignal => "ControlSignal",
            IntentCode::Telemetry => "Telemetry",
            IntentCode::AgentCoordinate => "AgentCoordinate",
            IntentCode::FileTransfer => "FileTransfer",
            IntentCode::Heartbeat => "Heartbeat",
        }
    }
}

impl fmt::Display for IntentCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ────────────────────────── Errors ──────────────────────────

/// Errors that can occur during header parsing or validation.
#[derive(Debug, Error)]
pub enum HeaderError {
    /// Buffer is too short to contain a valid AITP header.
    #[error("buffer too short: expected at least {expected} bytes, got {got}")]
    BufferTooShort { expected: usize, got: usize },

    /// Unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Payload length exceeds the remaining buffer.
    #[error("payload length {declared} exceeds available data {available}")]
    PayloadLengthMismatch { declared: usize, available: usize },

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),

    /// Invalid public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
}

// ────────────────────────── AITP Header ──────────────────────────

/// AITP packet header.
///
/// This struct represents the fixed 163-byte header prepended to every
/// AITP datagram. It is serialized using manual byte packing for
/// zero-overhead on the hot path.
///
/// # Signing
///
/// The [`signature`](AitpHeader::signature) field covers all header bytes
/// from offset 0 through offset 98 (inclusive), i.e., everything before
/// the signature itself. Use [`signable_bytes`](AitpHeader::signable_bytes)
/// to extract the signing payload.
#[derive(Clone)]
pub struct AitpHeader {
    /// Protocol version (4 bits, current: 1).
    pub version: u8,
    /// Packet flags (4 bits): SYN, ACK, FIN, REVOKE.
    pub flags: u8,
    /// Semantic intent code for this session/packet.
    pub intent_code: IntentCode,
    /// Unique session identifier.
    pub session_id: u64,
    /// Source identity: SHA-256 hash of sender's Ed25519 public key.
    pub source_id: [u8; 32],
    /// Destination identity: SHA-256 hash of receiver's Ed25519 public key.
    pub dest_id: [u8; 32],
    /// AI-assigned trust score (0–255).
    pub trust_score: u8,
    /// Reserved byte (must be 0).
    pub reserved: u8,
    /// Length of the payload in bytes.
    pub payload_len: u16,
    /// Timestamp: Unix epoch in nanoseconds.
    pub timestamp: u64,
    /// Nonce for replay protection (96 bits).
    pub nonce: [u8; 12],
    /// Ed25519 signature over all preceding header fields.
    pub signature: [u8; 64],
    /// Post-Quantum ML-DSA-65 signature.
    pub pq_signature: [u8; PQ_SIG_SIZE],
}

impl AitpHeader {
    /// Create a new header with required fields, zeroing signature.
    ///
    /// The caller must compute and set the signature via [`sign`](AitpHeader::sign)
    /// before transmitting.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flags: u8,
        intent_code: IntentCode,
        session_id: u64,
        source_id: [u8; 32],
        dest_id: [u8; 32],
        trust_score: u8,
        payload_len: u16,
        timestamp: u64,
        nonce: [u8; 12],
    ) -> Self {
        Self {
            version: AITP_VERSION,
            flags: flags & 0x0F, // Mask to 4 bits
            intent_code,
            session_id,
            source_id,
            dest_id,
            trust_score,
            reserved: 0,
            payload_len,
            timestamp,
            nonce,
            signature: [0u8; 64],
            pq_signature: [0u8; PQ_SIG_SIZE],
        }
    }

    /// Serialize the header to bytes (163 bytes, big-endian).
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` of exactly [`HEADER_SIZE`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);

        // Byte 0: version (high nibble) | flags (low nibble)
        buf.push((self.version << 4) | (self.flags & 0x0F));

        // Bytes 1–2: intent code (u16 BE)
        buf.extend_from_slice(&(self.intent_code as u16).to_be_bytes());

        // Bytes 3–10: session ID (u64 BE)
        buf.extend_from_slice(&self.session_id.to_be_bytes());

        // Bytes 11–42: source identity ID (32 bytes)
        buf.extend_from_slice(&self.source_id);

        // Bytes 43–74: destination identity ID (32 bytes)
        buf.extend_from_slice(&self.dest_id);

        // Byte 75: trust score
        buf.push(self.trust_score);

        // Byte 76: reserved
        buf.push(self.reserved);

        // Bytes 77–78: payload length (u16 BE)
        buf.extend_from_slice(&self.payload_len.to_be_bytes());

        // Bytes 79–86: timestamp (u64 BE)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // Bytes 87–98: nonce (12 bytes)
        buf.extend_from_slice(&self.nonce);

        // Bytes 99–162: signature (64 bytes)
        buf.extend_from_slice(&self.signature);

        // Bytes 163–3471: PQ signature (3309 bytes)
        buf.extend_from_slice(&self.pq_signature);

        debug_assert_eq!(buf.len(), HEADER_SIZE);
        buf
    }

    /// Deserialize a header from a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::BufferTooShort`] if the buffer is smaller
    /// than [`HEADER_SIZE`] bytes. Returns [`HeaderError::UnsupportedVersion`]
    /// if the version nibble is not [`AITP_VERSION`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self, HeaderError> {
        if buf.len() < HEADER_SIZE {
            return Err(HeaderError::BufferTooShort {
                expected: HEADER_SIZE,
                got: buf.len(),
            });
        }

        // Byte 0: version | flags
        let version = buf[0] >> 4;
        let flags_val = buf[0] & 0x0F;

        if version != AITP_VERSION {
            return Err(HeaderError::UnsupportedVersion(version));
        }

        // Bytes 1–2: intent code
        let intent_raw = u16::from_be_bytes([buf[1], buf[2]]);
        let intent_code = IntentCode::from_u16(intent_raw);

        // Bytes 3–10: session ID
        let session_id = u64::from_be_bytes(buf[3..11].try_into().unwrap());

        // Bytes 11–42: source ID
        let mut source_id = [0u8; 32];
        source_id.copy_from_slice(&buf[11..43]);

        // Bytes 43–74: dest ID
        let mut dest_id = [0u8; 32];
        dest_id.copy_from_slice(&buf[43..75]);

        // Byte 75: trust score
        let trust_score = buf[75];

        // Byte 76: reserved
        let reserved = buf[76];

        // Bytes 77–78: payload length
        let payload_len = u16::from_be_bytes([buf[77], buf[78]]);

        // Bytes 79–86: timestamp
        let timestamp = u64::from_be_bytes(buf[79..87].try_into().unwrap());

        // Bytes 87–98: nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[87..99]);

        // Bytes 99–162: signature
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[99..163]);

        // Bytes 163–3471: PQ signature
        let mut pq_signature = [0u8; PQ_SIG_SIZE];
        pq_signature.copy_from_slice(&buf[163..163 + PQ_SIG_SIZE]);

        Ok(Self {
            version,
            flags: flags_val,
            intent_code,
            session_id,
            source_id,
            dest_id,
            trust_score,
            reserved,
            payload_len,
            timestamp,
            nonce,
            signature,
            pq_signature,
        })
    }

    /// Extract the bytes that are covered by the signature.
    ///
    /// This is the header bytes from offset 0 through 98 (99 bytes),
    /// i.e., everything before the signature field.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let full = self.to_bytes();
        full[..99].to_vec()
    }

    /// Sign this header using the given AitpIdentity (hybrid).
    ///
    /// Computes the signature over [`signable_bytes`](AitpHeader::signable_bytes)
    /// and stores it in the `signature` and `pq_signature` fields.
    pub fn sign_hybrid(&mut self, identity: &AitpIdentity) {
        let msg = self.signable_bytes();
        let hybrid_sig = identity.sign_hybrid(&msg);
        self.signature.copy_from_slice(&hybrid_sig.classical);
        // Note: PQ signature depends strictly on the size constraint
        if hybrid_sig.pq.len() == PQ_SIG_SIZE {
            self.pq_signature.copy_from_slice(&hybrid_sig.pq);
        } else {
            tracing::warn!(
                "PQ signature length mismatch: expected {}, got {}",
                PQ_SIG_SIZE,
                hybrid_sig.pq.len()
            );
        }
    }

    /// Backwards compatibility wrapper that only signs classically.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let msg = self.signable_bytes();
        let sig = signing_key.sign(&msg);
        self.signature = sig.to_bytes();
    }

    /// Verify the header signature against the hybrid public keys.
    ///
    /// # Errors
    /// Returns [`HeaderError::InvalidSignature`] if verification fails.
    pub fn verify_signature_hybrid(
        &self,
        classical_pk: &[u8; 32],
        pq_pk: &mldsa65::PublicKey,
    ) -> Result<(), HeaderError> {
        let msg = self.signable_bytes();
        let hybrid_sig = HybridSignature {
            classical: self.signature.to_vec(),
            pq: self.pq_signature.to_vec(),
        };

        aitp_identity::identity::verify_hybrid_with_pubkeys(classical_pk, pq_pk, &msg, &hybrid_sig)
            .map_err(|e| HeaderError::InvalidSignature(e.to_string()))
    }

    /// Verify classically (for legacy nodes or tests).
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<(), HeaderError> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| HeaderError::InvalidPublicKey(e.to_string()))?;

        let sig = Signature::from_bytes(&self.signature);
        let msg = self.signable_bytes();

        verifying_key
            .verify(&msg, &sig)
            .map_err(|e| HeaderError::InvalidSignature(e.to_string()))
    }

    /// Check if a specific flag is set.
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Check if this is a SYN packet (handshake initiation).
    pub fn is_syn(&self) -> bool {
        self.has_flag(flags::SYN)
    }

    /// Check if this is an ACK packet.
    pub fn is_ack(&self) -> bool {
        self.has_flag(flags::ACK)
    }

    /// Check if this is a FIN packet (graceful close).
    pub fn is_fin(&self) -> bool {
        self.has_flag(flags::FIN)
    }

    /// Check if this is a REVOKE packet (immediate termination).
    pub fn is_revoke(&self) -> bool {
        self.has_flag(flags::REVOKE)
    }
}

impl fmt::Debug for AitpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AitpHeader")
            .field("version", &self.version)
            .field("flags", &format!("{:#06b}", self.flags))
            .field("intent_code", &self.intent_code)
            .field("session_id", &format!("{:#018x}", self.session_id))
            .field("source_id", &hex_short(&self.source_id))
            .field("dest_id", &hex_short(&self.dest_id))
            .field("trust_score", &self.trust_score)
            .field("payload_len", &self.payload_len)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Format a byte slice as a short hex string (first 4 bytes + "...").
fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 4 {
        hex::encode(bytes)
    } else {
        format!("{}...", hex::encode(&bytes[..4]))
    }
}

/// Tiny hex encoder (avoids adding the `hex` crate for this one use).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Helper: generate a test identity (signing key + entity ID).
    fn test_identity() -> (SigningKey, [u8; 32]) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let entity_id: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
        (signing_key, entity_id)
    }

    /// Helper: build a test header with reasonable defaults.
    fn test_header(source_id: [u8; 32], dest_id: [u8; 32]) -> AitpHeader {
        AitpHeader::new(
            flags::SYN,
            IntentCode::ModelInference,
            0xDEADBEEF12345678,
            source_id,
            dest_id,
            187,
            256,
            1_700_000_000_000_000_000, // ~2023 timestamp in ns
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        )
    }

    #[test]
    fn test_header_serialization_roundtrip() {
        let (_, src_id) = test_identity();
        let (_, dst_id) = test_identity();
        let original = test_header(src_id, dst_id);

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE, "Header size mismatch");

        let parsed = AitpHeader::from_bytes(&bytes).expect("Failed to parse header");

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.intent_code, original.intent_code);
        assert_eq!(parsed.session_id, original.session_id);
        assert_eq!(parsed.source_id, original.source_id);
        assert_eq!(parsed.dest_id, original.dest_id);
        assert_eq!(parsed.trust_score, original.trust_score);
        assert_eq!(parsed.reserved, original.reserved);
        assert_eq!(parsed.payload_len, original.payload_len);
        assert_eq!(parsed.timestamp, original.timestamp);
        assert_eq!(parsed.nonce, original.nonce);
        assert_eq!(parsed.signature, original.signature);
        assert_eq!(parsed.pq_signature.len(), original.pq_signature.len());
    }

    #[test]
    fn test_header_size_constant() {
        let header = test_header([0u8; 32], [0u8; 32]);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        assert_eq!(HEADER_SIZE, 3472);
    }

    #[test]
    fn test_version_flags_byte_encoding() {
        let header = AitpHeader::new(
            flags::SYN | flags::ACK,
            IntentCode::Heartbeat,
            0,
            [0u8; 32],
            [0u8; 32],
            0,
            0,
            0,
            [0u8; 12],
        );
        let bytes = header.to_bytes();
        // Version 1 in high nibble, SYN|ACK (0b0011) in low nibble
        assert_eq!(bytes[0], 0x13);
    }

    #[test]
    fn test_flags_checking() {
        let header = AitpHeader::new(
            flags::SYN | flags::FIN,
            IntentCode::Unknown,
            0,
            [0u8; 32],
            [0u8; 32],
            0,
            0,
            0,
            [0u8; 12],
        );
        assert!(header.is_syn());
        assert!(!header.is_ack());
        assert!(header.is_fin());
        assert!(!header.is_revoke());
    }

    #[test]
    fn test_all_flags_set() {
        let all_flags = flags::SYN | flags::ACK | flags::FIN | flags::REVOKE;
        let header = AitpHeader::new(
            all_flags,
            IntentCode::Unknown,
            0,
            [0u8; 32],
            [0u8; 32],
            0,
            0,
            0,
            [0u8; 12],
        );
        assert!(header.is_syn());
        assert!(header.is_ack());
        assert!(header.is_fin());
        assert!(header.is_revoke());
        assert_eq!(header.flags, 0x0F);
    }

    #[test]
    fn test_intent_code_roundtrip() {
        let intents = [
            IntentCode::Unknown,
            IntentCode::ModelInference,
            IntentCode::DataSync,
            IntentCode::ControlSignal,
            IntentCode::Telemetry,
            IntentCode::AgentCoordinate,
            IntentCode::FileTransfer,
            IntentCode::Heartbeat,
        ];

        for intent in intents {
            let raw = intent as u16;
            let parsed = IntentCode::from_u16(raw);
            assert_eq!(parsed, intent, "IntentCode roundtrip failed for {intent:?}");
        }
    }

    #[test]
    fn test_unknown_intent_code() {
        assert_eq!(IntentCode::from_u16(0xFFFF), IntentCode::Unknown);
        assert_eq!(IntentCode::from_u16(0x9999), IntentCode::Unknown);
    }

    #[test]
    fn test_buffer_too_short() {
        let short_buf = vec![0u8; 50];
        let result = AitpHeader::from_bytes(&short_buf);
        assert!(matches!(result, Err(HeaderError::BufferTooShort { .. })));
    }

    #[test]
    fn test_unsupported_version() {
        let mut buf = vec![0u8; HEADER_SIZE];
        // Set version to 15 (high nibble)
        buf[0] = 0xF0;
        let result = AitpHeader::from_bytes(&buf);
        assert!(matches!(result, Err(HeaderError::UnsupportedVersion(15))));
    }

    #[test]
    fn test_max_payload_length() {
        let header = AitpHeader::new(
            0,
            IntentCode::FileTransfer,
            1,
            [0u8; 32],
            [0u8; 32],
            128,
            u16::MAX,
            0,
            [0u8; 12],
        );
        let bytes = header.to_bytes();
        let parsed = AitpHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload_len, u16::MAX);
    }

    #[test]
    fn test_sign_and_verify() {
        let (src_key, src_id) = test_identity();
        let (_, dst_id) = test_identity();

        let mut header = test_header(src_id, dst_id);
        header.sign(&src_key);

        // Signature should now be non-zero
        assert_ne!(header.signature, [0u8; 64]);

        // Verify against the source's public key
        let pub_key_bytes: [u8; 32] = *src_key.verifying_key().as_bytes();
        header
            .verify_signature(&pub_key_bytes)
            .expect("Signature should be valid");
    }

    #[test]
    fn test_sign_and_verify_hybrid() {
        let id_src =
            AitpIdentity::generate("src", aitp_identity::identity::EntityType::Service, vec![]);
        let id_dst =
            AitpIdentity::generate("dst", aitp_identity::identity::EntityType::Service, vec![]);

        let mut header = test_header(id_src.entity_id, id_dst.entity_id);
        header.sign_hybrid(&id_src);

        assert_ne!(header.signature, [0u8; 64]);
        assert_ne!(header.pq_signature[0..10], [0u8; 10]);

        header
            .verify_signature_hybrid(&id_src.public_key_bytes(), &id_src.pq_public_key)
            .expect("Hybrid signature should be valid");
    }

    #[test]
    fn test_tampered_header_fails_verification() {
        let (src_key, src_id) = test_identity();
        let (_, dst_id) = test_identity();

        let mut header = test_header(src_id, dst_id);
        header.sign(&src_key);

        // Tamper with the trust score
        header.trust_score = 0;

        let pub_key_bytes: [u8; 32] = *src_key.verifying_key().as_bytes();
        let result = header.verify_signature(&pub_key_bytes);
        assert!(result.is_err(), "Tampered header should fail verification");
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let (src_key, src_id) = test_identity();
        let (_, dst_id) = test_identity();
        let (other_key, _) = test_identity();

        let mut header = test_header(src_id, dst_id);
        header.sign(&src_key);

        // Verify with wrong key
        let wrong_key: [u8; 32] = *other_key.verifying_key().as_bytes();
        let result = header.verify_signature(&wrong_key);
        assert!(result.is_err(), "Wrong key should fail verification");
    }

    #[test]
    fn test_signable_bytes_stability() {
        let header = test_header([0xAA; 32], [0xBB; 32]);
        let signable1 = header.signable_bytes();
        let signable2 = header.signable_bytes();
        assert_eq!(
            signable1, signable2,
            "Signable bytes should be deterministic"
        );
        assert_eq!(signable1.len(), 99, "Signable region is 99 bytes");
    }

    #[test]
    fn test_serialization_with_extra_buffer() {
        // Parsing a buffer larger than HEADER_SIZE should succeed
        // (extra bytes are payload or padding)
        let header = test_header([0u8; 32], [0u8; 32]);
        let mut buf = header.to_bytes();
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // extra bytes

        let parsed = AitpHeader::from_bytes(&buf).unwrap();
        assert_eq!(parsed.version, AITP_VERSION);
    }

    #[test]
    fn test_session_id_endianness() {
        let header = AitpHeader::new(
            0,
            IntentCode::Unknown,
            0x0123456789ABCDEF,
            [0u8; 32],
            [0u8; 32],
            0,
            0,
            0,
            [0u8; 12],
        );
        let bytes = header.to_bytes();
        // Session ID at offset 3, big-endian
        assert_eq!(bytes[3], 0x01);
        assert_eq!(bytes[4], 0x23);
        assert_eq!(bytes[10], 0xEF);
    }

    #[test]
    fn test_intent_code_display() {
        assert_eq!(IntentCode::ModelInference.to_string(), "ModelInference");
        assert_eq!(IntentCode::Heartbeat.to_string(), "Heartbeat");
    }
}
