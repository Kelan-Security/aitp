use serde::{Deserialize, Serialize};

/// The cryptographic algorithm set used by an entity.
/// Advertised in the AITP_HELLO packet (version field extended).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CryptoAlgorithm {
    /// Ed25519 only — legacy clients, pre-v0.4
    Classical = 0x01,
    /// Ed25519 + ML-DSA-65 hybrid — new default from v0.4
    HybridPQ = 0x02,
    /// ML-DSA-65 only — future-only mode, defense deployments
    PostQuantum = 0x03,
}

impl CryptoAlgorithm {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Classical),
            0x02 => Some(Self::HybridPQ),
            0x03 => Some(Self::PostQuantum),
            _ => None,
        }
    }

    pub fn is_pq_capable(&self) -> bool {
        matches!(self, Self::HybridPQ | Self::PostQuantum)
    }

    /// Minimum algorithm required by server policy.
    /// Classical: accept any. HybridPQ: reject Classical-only.
    /// PostQuantum: accept only PostQuantum.
    pub fn satisfies_policy(&self, policy: CryptoAlgorithm) -> bool {
        match policy {
            CryptoAlgorithm::Classical => true,
            CryptoAlgorithm::HybridPQ => self.is_pq_capable(),
            CryptoAlgorithm::PostQuantum => *self == CryptoAlgorithm::PostQuantum,
        }
    }
}
