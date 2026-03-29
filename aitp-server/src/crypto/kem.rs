//! ML-KEM-768 (FIPS 203, formerly Kyber-768) key encapsulation.
//!
//! Used during session establishment to derive a shared secret.
//! Replaces X25519 ECDH in post-quantum mode.
//! In hybrid mode: both X25519 and ML-KEM-768 run, shared secret =
//! KDF(x25519_shared || mlkem_shared) — breaks if EITHER is broken.

use pqcrypto_mlkem::mlkem768::{self, PublicKey as KemPk, SecretKey as KemSk, Ciphertext};
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, SharedSecret as PqSharedSecret};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pk};
use sha3::{Sha3_256, Digest};
use rand::rngs::OsRng;

/// A derived shared secret from the hybrid KEM operation.
/// Zeroized on drop.
pub struct SharedSecret(pub [u8; crate::crypto::MLKEM768_SS_BYTES]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Hybrid KEM: X25519 + ML-KEM-768.
pub struct HybridKem;

impl HybridKem {
    /// Initiator side: generate an ephemeral keypair, encapsulate.
    /// Returns: (classical_public, pq_ciphertext, shared_secret)
    /// Send classical_public + pq_ciphertext to the responder.
    pub fn encapsulate(
        responder_classical: &X25519Pk,
        responder_pq:        &KemPk,
    ) -> (X25519Pk, Vec<u8>, SharedSecret) {
        // Classical: X25519 ephemeral DH
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pk = X25519Pk::from(&ephemeral);
        let classical_shared = ephemeral.diffie_hellman(responder_classical);

        // Post-quantum: ML-KEM-768 encapsulation
        let (pq_shared, pq_ct) = mlkem768::encapsulate(responder_pq);

        // Combine: shared = SHA3-256(x25519_ss || mlkem_ss)
        let mut hasher = Sha3_256::new();
        hasher.update(classical_shared.as_bytes());
        hasher.update(pq_shared.as_bytes());
        let combined: [u8; 32] = hasher.finalize().into();

        (ephemeral_pk, pq_ct.as_bytes().to_vec(), SharedSecret(combined))
    }

    /// Responder side: decapsulate to get the same shared secret.
    pub fn decapsulate(
        our_classical_sk: x25519_dalek::StaticSecret,
        our_pq_sk:        &KemSk,
        their_classical_pk: &X25519Pk,
        pq_ciphertext:    &[u8],
    ) -> anyhow::Result<SharedSecret> {
        // Classical: X25519 DH
        let classical_shared = our_classical_sk.diffie_hellman(their_classical_pk);

        // Post-quantum: ML-KEM-768 decapsulation
        if pq_ciphertext.len() != crate::crypto::MLKEM768_CT_BYTES {
            return Err(anyhow::anyhow!("Invalid ML-KEM-768 ciphertext length. Expected {}", crate::crypto::MLKEM768_CT_BYTES));
        }
        let ct = Ciphertext::from_bytes(pq_ciphertext)
            .map_err(|_| anyhow::anyhow!("Invalid ML-KEM-768 ciphertext"))?;
        let pq_shared = mlkem768::decapsulate(&ct, our_pq_sk);

        // Derive combined shared secret
        let mut hasher = Sha3_256::new();
        hasher.update(classical_shared.as_bytes());
        hasher.update(pq_shared.as_bytes());
        let combined: [u8; 32] = hasher.finalize().into();

        Ok(SharedSecret(combined))
    }
}
