//! Kelan Security — Cryptographic Primitives
//!
//! Hybrid classical + post-quantum cryptography.
//! Classical:     Ed25519 signatures, X25519 key exchange
//! Post-quantum:  ML-DSA-65 signatures (FIPS 204), ML-KEM-768 (FIPS 203)
//! Hybrid:        Both classical AND post-quantum simultaneously
//!
//! Security model: an attacker must break BOTH schemes to forge signatures.
//! Safe today (classical hardness) AND safe against quantum computers (PQ).

pub mod identity;
pub mod hybrid_sig;
pub mod kem;
pub mod algorithm;

pub use algorithm::CryptoAlgorithm;
pub use identity::HybridEntityIdentity;
pub use hybrid_sig::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
pub use kem::{HybridKem, SharedSecret};

// ── Key size constants 
/// Ed25519 public key size in bytes
pub const ED25519_PK_BYTES:   usize = 32;
/// Ed25519 signature size in bytes
pub const ED25519_SIG_BYTES:  usize = 64;
/// ML-DSA-65 public key size in bytes (FIPS 204)
pub const MLDSA65_PK_BYTES:   usize = 1952;
/// ML-DSA-65 signature size in bytes
pub const MLDSA65_SIG_BYTES:  usize = 3309;
/// ML-KEM-768 public key size in bytes (FIPS 203)
pub const MLKEM768_PK_BYTES:  usize = 1184;
/// ML-KEM-768 ciphertext size in bytes
pub const MLKEM768_CT_BYTES:  usize = 1088;
/// ML-KEM-768 shared secret size in bytes
pub const MLKEM768_SS_BYTES:  usize = 32;

/// Hybrid public key: Ed25519 (32) + ML-DSA-65 (1952) + type byte
pub const HYBRID_PK_BYTES: usize = 1 + ED25519_PK_BYTES + MLDSA65_PK_BYTES;

/// Hybrid signature: Ed25519 (64) + ML-DSA-65 (3309) + lengths
pub const HYBRID_SIG_BYTES: usize = ED25519_SIG_BYTES + MLDSA65_SIG_BYTES + 4;
