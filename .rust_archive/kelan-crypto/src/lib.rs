pub mod algorithm;
pub mod hybrid_sig;
pub mod identity;
pub mod kem;

pub use algorithm::CryptoAlgorithm;
pub use hybrid_sig::{CryptoError, HybridSignature, HybridSigningKey, HybridVerifyingKey};
pub use identity::HybridEntityIdentity;
pub use kem::{HybridKem, KemPublicKey, SharedSecret};
pub mod session;
pub use session::SessionKey;

// ── Key size constants
/// Ed25519 public key size in bytes
pub const ED25519_PK_BYTES: usize = 32;
/// Ed25519 signature size in bytes
pub const ED25519_SIG_BYTES: usize = 64;

/// ML-DSA-65 (Kyber) public key size
pub const MLDSA65_PK_BYTES: usize = 1952;
/// ML-DSA-65 signature size
pub const MLDSA65_SIG_BYTES: usize = 3309;

pub const MLKEM768_PK_BYTES: usize = 1184;

pub const MLKEM768_CT_BYTES: usize = 1088;

pub const MLKEM768_SS_BYTES: usize = 32;

/// Combined Hybrid Public Key: [32 Ed25519] [1952 ML-DSA] = 1984 bytes
pub const HYBRID_PK_BYTES: usize = ED25519_PK_BYTES + MLDSA65_PK_BYTES;

/// Combined Hybrid Signature: [4 length] [64 Ed25519] [N ML-DSA]
pub const HYBRID_SIG_BYTES: usize = ED25519_SIG_BYTES + MLDSA65_SIG_BYTES + 4;
