pub mod handshake;
pub mod session;

use serde::{Deserialize, Serialize};

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

// ────────────────────────── AitpHeaderV4 ──────────────────────────

/// AITP v4 packet header — variable length to accommodate PQ key material.
///
/// Fixed section (37 bytes):
///   version(1) + flags(1) + intent(2) + session_id(8) + timestamp(8) +
///   nonce(12) + algorithm(1) + pk_len(2) + sig_len(2)
///
/// Variable section:
///   source_id_pk[pk_len]   — public key (32 for classical, 1985 for hybrid)
///   dest_id[32]            — destination EntityID (always 32 bytes SHA-256)
///   signature[sig_len]     — signature over all above (64 or 3373 bytes)
///   payload_len(4)
///   payload[payload_len]   — AES-256-GCM encrypted
#[derive(Debug, Clone)]
pub struct AitpHeaderV4 {
    pub version:    u8,         // 4 for PQ-capable, 3 for legacy
    pub flags:      u8,         // SYN|ACK|FIN|RST|REVOKE
    pub intent:     u16,        // IntentCode
    pub session_id: u64,
    pub timestamp:  u64,        // Unix microseconds
    pub nonce:      [u8; 12],
    pub algorithm:  u8,         // CryptoAlgorithm byte
    pub source_pk:  Vec<u8>,    // public key (variable length)
    pub dest_id:    [u8; 32],   // SHA-256(dest_pubkey)
    pub signature:  Vec<u8>,    // hybrid or classical signature
    pub payload_len: u32,
}

impl AitpHeaderV4 {
    /// Serialise to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.push(self.flags);
        out.extend_from_slice(&self.intent.to_be_bytes());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.push(self.algorithm);
        out.extend_from_slice(&(self.source_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.source_pk);
        out.extend_from_slice(&self.dest_id);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.payload_len.to_be_bytes());
        out
    }

    /// The bytes covered by the signature (everything before the sig field)
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.push(self.flags);
        out.extend_from_slice(&self.intent.to_be_bytes());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.push(self.algorithm);
        out.extend_from_slice(&(self.source_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.source_pk);
        out.extend_from_slice(&self.dest_id);
        out
    }

    /// Parse from wire format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 37 {
            return Err("buffer too short for AITP v4 header fixed section");
        }
        let version = bytes[0];
        let flags = bytes[1];
        let intent = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let session_id = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        let timestamp = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        let nonce: [u8; 12] = bytes[20..32].try_into().unwrap();
        let algorithm = bytes[32];
        let pk_len = u16::from_be_bytes(bytes[33..35].try_into().unwrap()) as usize;
        let sig_len = u16::from_be_bytes(bytes[35..37].try_into().unwrap()) as usize;

        if sig_len > crate::crypto::HYBRID_SIG_BYTES {
            return Err("Signature exceeds maximum allowable post-quantum length");
        }

        let required_len = 37 + pk_len + 32 + sig_len + 4;
        if bytes.len() < required_len {
            return Err("buffer too short for AITP v4 header variable section");
        }

        let mut offset = 37;
        
        // Bounding check for ML-KEM/ML-DSA public keys
        if pk_len > crate::crypto::MLKEM768_PK_BYTES + crate::crypto::MLDSA65_SIG_BYTES + 32 {
            return Err("Public key exceeds theoretical max length for hybrid identity");
        }

        let source_pk = bytes[offset..offset + pk_len].to_vec();
        offset += pk_len;

        let dest_id: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
        offset += 32;

        let signature = bytes[offset..offset + sig_len].to_vec();
        offset += sig_len;

        let payload_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());

        Ok(Self {
            version,
            flags,
            intent,
            session_id,
            timestamp,
            nonce,
            algorithm,
            source_pk,
            dest_id,
            signature,
            payload_len,
        })
    }

    pub fn source_id(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.source_pk);
        hasher.finalize().into()
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn is_syn(&self) -> bool { self.has_flag(FLAG_SYN) }
    pub fn is_ack(&self) -> bool { self.has_flag(FLAG_ACK) }
    pub fn is_fin(&self) -> bool { self.has_flag(FLAG_FIN) }
    pub fn is_rst(&self) -> bool { self.has_flag(FLAG_RST) }
    pub fn is_revoke(&self) -> bool { self.has_flag(FLAG_REVOKE) }
}

// Map the generic name to V4 globally to prevent widespread renaming problems,
// but ensure usages accommodate variable length keys.
pub type AitpHeader = AitpHeaderV4;

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
    fn test_header_v4_serialize_roundtrip() {
        let hdr = AitpHeaderV4 {
            version: 4,
            flags: FLAG_SYN,
            intent: IntentCode::ModelInference as u16,
            session_id: 42,
            timestamp: 1000,
            nonce: [1u8; 12],
            algorithm: 2,
            source_pk: vec![1, 2, 3],
            dest_id: [2u8; 32],
            signature: vec![4, 5, 6, 7],
            payload_len: 256,
        };
        let bytes = hdr.to_bytes();

        let parsed = AitpHeaderV4::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.flags, FLAG_SYN);
        assert_eq!(parsed.intent, IntentCode::ModelInference as u16);
        assert_eq!(parsed.session_id, 42);
        assert_eq!(parsed.source_pk, vec![1, 2, 3]);
        assert_eq!(parsed.dest_id, [2u8; 32]);
        assert_eq!(parsed.payload_len, 256);
    }
}
