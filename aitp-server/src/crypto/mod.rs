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
// Re-export everything from the shared crate
pub use kelan_crypto::*;
