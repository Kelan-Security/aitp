pub mod handshake;
pub mod session;

use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref, Unaligned};

// ────────────────────────── Flags ──────────────────────────

/// AITP packet flags.
pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_ACK: u8 = 0x02;
pub const FLAG_FIN: u8 = 0x04;
pub const FLAG_RST: u8 = 0x08;
pub const FLAG_REVOKE: u8 = 0x10;

// ────────────────────────── IntentCode ──────────────────────────

/// AITP intent codes — what the session is *doing*.
#[repr(u16)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IntentCode {
    ModelInference = 0x0001,
    DataSync = 0x0002,
    ControlSignal = 0x0003,
    Telemetry = 0x0004,
    AgentCoordinate = 0x0005,
    FileTransfer = 0x0006,
    Heartbeat = 0x0007,
    Unknown = 0x00FF,
}

impl IntentCode {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0001 => IntentCode::ModelInference,
            0x0002 => IntentCode::DataSync,
            0x0003 => IntentCode::ControlSignal,
            0x0004 => IntentCode::Telemetry,
            0x0005 => IntentCode::AgentCoordinate,
            0x0006 => IntentCode::FileTransfer,
            0x0007 => IntentCode::Heartbeat,
            _ => IntentCode::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            IntentCode::ModelInference => "ModelInference",
            IntentCode::DataSync => "DataSync",
            IntentCode::ControlSignal => "ControlSignal",
            IntentCode::Telemetry => "Telemetry",
            IntentCode::AgentCoordinate => "AgentCoordinate",
            IntentCode::FileTransfer => "FileTransfer",
            IntentCode::Heartbeat => "Heartbeat",
            IntentCode::Unknown => "Unknown",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "ModelInference" => IntentCode::ModelInference,
            "DataSync" => IntentCode::DataSync,
            "ControlSignal" => IntentCode::ControlSignal,
            "Telemetry" => IntentCode::Telemetry,
            "AgentCoordinate" => IntentCode::AgentCoordinate,
            "FileTransfer" => IntentCode::FileTransfer,
            "Heartbeat" => IntentCode::Heartbeat,
            _ => IntentCode::Unknown,
        }
    }
}

impl std::fmt::Display for IntentCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ────────────────────────── AitpHeader ──────────────────────────

#[derive(Debug, AsBytes, FromBytes, FromZeroes, Unaligned)]
#[repr(C, packed)]
pub struct AitpHeaderWire {
    pub version:     u8,
    pub flags:       u8,
    pub intent:      [u8; 2],   // big-endian u16
    pub session_id:  [u8; 8],   // big-endian u64
    pub timestamp:   [u8; 8],
    pub nonce:       [u8; 12],
    pub source_id:   [u8; 32],
    pub dest_id:     [u8; 32],
    pub signature:   [u8; 64],
    pub payload_len: [u8; 4],
}

/// AITP packet header — 164 bytes on the wire.
#[derive(Debug, Clone)]
pub struct AitpHeader {
    pub version: u8,
    pub flags: u8,
    pub intent: u16,
    pub session_id: u64,
    pub timestamp: u64,      // unix microseconds
    pub nonce: [u8; 12],     // replay prevention
    pub source_id: [u8; 32], // SHA-256(Ed25519_pubkey)
    pub dest_id: [u8; 32],
    pub signature: [u8; 64], // Ed25519 signature
    pub payload_len: u32,
}

impl AitpHeader {
    /// Total header size in bytes.
    /// 1 (version) + 1 (flags) + 2 (intent) + 8 (session_id) + 8 (timestamp)
    /// + 12 (nonce) + 32 (source_id) + 32 (dest_id) + 64 (signature) + 4 (payload_len)
    ///   = 164 bytes.
    pub const SIZE: usize = 164;

    /// Create a new header (signature zeroed — call sign() before sending).
    pub fn new(
        flags: u8,
        intent: IntentCode,
        session_id: u64,
        source_id: [u8; 32],
        dest_id: [u8; 32],
        payload_len: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let mut nonce = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);

        Self {
            version: 1,
            flags,
            intent: intent as u16,
            session_id,
            timestamp: now,
            nonce,
            source_id,
            dest_id,
            signature: [0u8; 64],
            payload_len,
        }
    }

    /// Serialize the header to bytes (big-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.push(self.version);
        buf.push(self.flags);
        buf.extend_from_slice(&self.intent.to_be_bytes());
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.source_id);
        buf.extend_from_slice(&self.dest_id);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    /// Deserialize from a byte buffer using zero-copy.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < Self::SIZE {
            return Err("buffer too short for AITP header");
        }

        let wire = Ref::<_, AitpHeaderWire>::new_unaligned(&buf[..Self::SIZE])
            .ok_or("failed to align AITP header")?
            .into_ref();

        if wire.version != 1 {
            return Err("unsupported AITP version");
        }

        Ok(Self {
            version: wire.version,
            flags: wire.flags,
            intent: u16::from_be_bytes(wire.intent),
            session_id: u64::from_be_bytes(wire.session_id),
            timestamp: u64::from_be_bytes(wire.timestamp),
            nonce: wire.nonce,
            source_id: wire.source_id,
            dest_id: wire.dest_id,
            signature: wire.signature,
            payload_len: u32::from_be_bytes(wire.payload_len),
        })
    }

    /// Bytes covered by the signature (everything before the signature field).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let full = self.to_bytes();
        full[..96].to_vec()
    }

    /// Check if a flag is set.
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn is_syn(&self) -> bool {
        self.has_flag(FLAG_SYN)
    }
    pub fn is_ack(&self) -> bool {
        self.has_flag(FLAG_ACK)
    }
    pub fn is_fin(&self) -> bool {
        self.has_flag(FLAG_FIN)
    }
    pub fn is_rst(&self) -> bool {
        self.has_flag(FLAG_RST)
    }
    pub fn is_revoke(&self) -> bool {
        self.has_flag(FLAG_REVOKE)
    }
}

/// Verify the Ed25519 signature on an AITP header.
pub fn verify_header_signature(header: &AitpHeader, pubkey: &[u8; 32]) -> bool {
    use ed25519_dalek::Verifier;
    use ed25519_dalek::{Signature, VerifyingKey};

    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let sig = Signature::from_bytes(&header.signature);
    let msg = header.signable_bytes();
    vk.verify(&msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_code_roundtrip() {
        assert_eq!(IntentCode::from_u16(0x0001), IntentCode::ModelInference);
        assert_eq!(IntentCode::from_u16(0x0003), IntentCode::ControlSignal);
        assert_eq!(IntentCode::from_u16(0xBEEF), IntentCode::Unknown);
    }

    #[test]
    fn test_intent_code_str() {
        assert_eq!(IntentCode::ModelInference.as_str(), "ModelInference");
        assert_eq!(
            IntentCode::from_str_loose("Heartbeat"),
            IntentCode::Heartbeat
        );
    }

    #[test]
    fn test_header_serialize_roundtrip() {
        let hdr = AitpHeader::new(
            FLAG_SYN,
            IntentCode::ModelInference,
            42,
            [1u8; 32],
            [2u8; 32],
            256,
        );
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), AitpHeader::SIZE);

        let parsed = AitpHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.flags, FLAG_SYN);
        assert_eq!(parsed.intent, IntentCode::ModelInference as u16);
        assert_eq!(parsed.session_id, 42);
        assert_eq!(parsed.source_id, [1u8; 32]);
        assert_eq!(parsed.dest_id, [2u8; 32]);
        assert_eq!(parsed.payload_len, 256);
    }

    #[test]
    fn test_header_flags() {
        let hdr = AitpHeader::new(
            FLAG_SYN | FLAG_ACK,
            IntentCode::DataSync,
            1,
            [0u8; 32],
            [0u8; 32],
            0,
        );
        assert!(hdr.is_syn());
        assert!(hdr.is_ack());
        assert!(!hdr.is_fin());
        assert!(!hdr.is_rst());
        assert!(!hdr.is_revoke());
    }

    #[test]
    fn test_header_too_short() {
        assert!(AitpHeader::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_verify_signature_invalid() {
        // Generate a real keypair so verifying key is valid,
        // but the header signature is all zeros → verification should fail.
        let (_, pk) = crate::identity::crypto::generate_keypair();
        let hdr = AitpHeader::new(
            FLAG_SYN,
            IntentCode::ModelInference,
            1,
            [0u8; 32],
            [0u8; 32],
            0,
        );
        assert!(!verify_header_signature(&hdr, &pk));
    }
}
