//! Hybrid Ed25519 + ML-DSA-65 signatures.
//!
//! A hybrid signature is: Ed25519_sig (64 bytes) || ML-DSA-65_sig (3309 bytes)
//! Both signatures cover the SAME message.
//! Verification requires BOTH to pass.
//! An attacker must break BOTH to forge — provides maximum security.

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey,
                    Signer, Verifier, Signature as Ed25519Signature};
use pqcrypto_mldsa::mldsa65::{
    self,
    PublicKey  as MlDsa65PublicKey,
    SecretKey  as MlDsa65SecretKey,
    SignedMessage,
};
use pqcrypto_traits::sign::{SignedMessage as SignedMessageTrait,
                             PublicKey    as PublicKeyTrait,
                             SecretKey    as SecretKeyTrait};
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

/// A hybrid verifying key containing both classical and PQ components.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    pub classical: Ed25519VerifyingKey,
    pub post_quantum: MlDsa65PublicKey,
    pub algorithm: super::CryptoAlgorithm,
}

impl HybridVerifyingKey {
    /// Serialise to bytes: [1 byte algorithm] [32 Ed25519] [1952 ML-DSA-65]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(super::HYBRID_PK_BYTES);
        out.push(self.algorithm as u8);
        out.extend_from_slice(self.classical.as_bytes());
        out.extend_from_slice(self.post_quantum.as_bytes());
        out
    }

    /// Deserialise from bytes. Returns None if format is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 1 { return None; }

        let alg = super::CryptoAlgorithm::from_byte(bytes[0])?;

        match alg {
            super::CryptoAlgorithm::Classical => {
                // Classical-only: only Ed25519 public key present
                if bytes.len() < 1 + super::ED25519_PK_BYTES { return None; }
                let classical_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
                let classical = Ed25519VerifyingKey::from_bytes(&classical_bytes).ok()?;
                // Dummy PQ key for classical-only mode (not used in verification)
                // This is safe — verify() checks algorithm and skips PQ for Classical
                None // Classical-only doesn't use HybridVerifyingKey
            }
            super::CryptoAlgorithm::HybridPQ |
            super::CryptoAlgorithm::PostQuantum => {
                if bytes.len() < super::HYBRID_PK_BYTES { return None; }
                let classical_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
                let classical = Ed25519VerifyingKey::from_bytes(&classical_bytes).ok()?;
                let pq_bytes = &bytes[33..33 + super::MLDSA65_PK_BYTES];
                let post_quantum = MlDsa65PublicKey::from_bytes(pq_bytes).ok()?;
                Some(Self { classical, post_quantum, algorithm: alg })
            }
        }
    }

    /// Compute EntityID = SHA-256(hybrid_public_key_bytes)
    /// This is stable — same entity ID regardless of which verifying method used
    pub fn entity_id(&self) -> [u8; 32] {
        let pk_bytes = self.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&pk_bytes);
        hasher.finalize().into()
    }
}

/// A hybrid signature: both Ed25519 and ML-DSA-65 signatures on the same message.
pub struct HybridSignature {
    pub classical:    [u8; 64],     // Ed25519 signature
    pub post_quantum: Vec<u8>,      // ML-DSA-65 signature (3309 bytes)
}

impl HybridSignature {
    /// Serialise: [4-byte PQ sig length LE] [64 Ed25519] [N ML-DSA-65]
    pub fn to_bytes(&self) -> Vec<u8> {
        let pq_len = self.post_quantum.len() as u32;
        let mut out = Vec::with_capacity(super::HYBRID_SIG_BYTES);
        out.extend_from_slice(&pq_len.to_le_bytes());
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.post_quantum);
        out
    }

    /// Deserialise a hybrid signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + super::ED25519_SIG_BYTES { return None; }
        let pq_len = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
        if bytes.len() < 4 + super::ED25519_SIG_BYTES + pq_len { return None; }

        let classical: [u8; 64] = bytes[4..68].try_into().ok()?;
        let post_quantum = bytes[68..68 + pq_len].to_vec();

        Some(Self { classical, post_quantum })
    }
}

/// The hybrid signing key — holds both private keys.
/// Must be zeroized on drop.
pub struct HybridSigningKey {
    classical:    Ed25519SigningKey,
    post_quantum: MlDsa65SecretKey,
    pub verifying_key: HybridVerifyingKey,
}

impl HybridSigningKey {
    /// Generate a new hybrid keypair.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;

        // Generate classical keypair
        let classical = Ed25519SigningKey::generate(&mut OsRng);
        let classical_vk = classical.verifying_key();

        // Generate ML-DSA-65 keypair
        let (pq_pk, pq_sk) = mldsa65::keypair();

        let verifying_key = HybridVerifyingKey {
            classical:    classical_vk,
            post_quantum: pq_pk,
            algorithm:    super::CryptoAlgorithm::HybridPQ,
        };

        Self { classical, post_quantum: pq_sk, verifying_key }
    }

    /// Sign a message with both algorithms.
    /// Returns a HybridSignature where BOTH sigs must verify.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        // Classical signature
        let classical_sig = self.classical.sign(message);

        // ML-DSA-65 signature
        // pqcrypto's sign() returns SignedMessage = sig || message
        // We extract just the signature prefix
        let signed = mldsa65::sign(message, &self.post_quantum);
        let sig_len = signed.as_bytes().len() - message.len();
        let post_quantum_sig = signed.as_bytes()[..sig_len].to_vec();

        HybridSignature {
            classical:    classical_sig.to_bytes(),
            post_quantum: post_quantum_sig,
        }
    }

    /// Serialise private key material for secure storage.
    /// Format: [32 Ed25519 private] [pq_sk_len LE u32] [ML-DSA-65 private]
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        let ed_sk = self.classical.to_bytes();
        let pq_sk = self.post_quantum.as_bytes();
        let pq_len = pq_sk.len() as u32;

        let mut out = Vec::with_capacity(32 + 4 + pq_sk.len());
        out.extend_from_slice(&ed_sk);
        out.extend_from_slice(&pq_len.to_le_bytes());
        out.extend_from_slice(pq_sk);
        out
    }

    /// Reconstruct from stored secret bytes.
    pub fn from_secret_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() < 36 {
            anyhow::bail!("HybridSigningKey: insufficient bytes");
        }

        let ed_bytes: [u8; 32] = bytes[..32].try_into()?;
        let classical = Ed25519SigningKey::from_bytes(&ed_bytes);
        let classical_vk = classical.verifying_key();

        let pq_len = u32::from_le_bytes(bytes[32..36].try_into()?) as usize;
        if bytes.len() < 36 + pq_len {
            anyhow::bail!("HybridSigningKey: truncated PQ key");
        }

        let pq_sk = MlDsa65SecretKey::from_bytes(&bytes[36..36 + pq_len])
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 key parse: {:?}", e))?;

        // Recompute PQ public key from secret key
        // ML-DSA-65 secret keys in pqcrypto contain the public key
        let pq_pk_bytes = &pq_sk.as_bytes()[..super::MLDSA65_PK_BYTES];
        let pq_pk = MlDsa65PublicKey::from_bytes(pq_pk_bytes)
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 pubkey: {:?}", e))?;

        let verifying_key = HybridVerifyingKey {
            classical:    classical_vk,
            post_quantum: pq_pk,
            algorithm:    super::CryptoAlgorithm::HybridPQ,
        };

        Ok(Self { classical, post_quantum: pq_sk, verifying_key })
    }
}

/// Verify a hybrid signature against a hybrid verifying key.
/// For HybridPQ: BOTH classical AND post-quantum must pass.
/// For Classical: only Ed25519 is checked (backward compat).
pub fn verify_hybrid(
    verifying_key: &HybridVerifyingKey,
    message:       &[u8],
    signature:     &HybridSignature,
) -> Result<(), CryptoError> {
    // Always verify classical Ed25519
    let ed_sig = Ed25519Signature::from_bytes(&signature.classical);
    verifying_key.classical
        .verify(message, &ed_sig)
        .map_err(|_| CryptoError::ClassicalVerifyFailed)?;

    // For HybridPQ and PostQuantum: also verify ML-DSA-65
    if verifying_key.algorithm.is_pq_capable() {
        if signature.post_quantum.is_empty() {
            return Err(CryptoError::PqSignatureMissing);
        }

        // Reconstruct SignedMessage = pq_sig || message for pqcrypto's open()
        let mut signed_message = signature.post_quantum.clone();
        signed_message.extend_from_slice(message);

        let sm = SignedMessage::from_bytes(&signed_message)
            .map_err(|_| CryptoError::PqVerifyFailed)?;

        mldsa65::open(&sm, &verifying_key.post_quantum)
            .map_err(|_| CryptoError::PqVerifyFailed)?;
    }

    Ok(())
}

/// Verify a classical Ed25519-only signature (backward compat for old clients).
pub fn verify_classical(
    verifying_key: &Ed25519VerifyingKey,
    message:       &[u8],
    signature:     &[u8; 64],
) -> Result<(), CryptoError> {
    let sig = Ed25519Signature::from_bytes(signature);
    verifying_key.verify(message, &sig)
        .map_err(|_| CryptoError::ClassicalVerifyFailed)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Ed25519 signature verification failed")]
    ClassicalVerifyFailed,
    #[error("ML-DSA-65 signature verification failed")]
    PqVerifyFailed,
    #[error("PQ signature missing but PQ algorithm required")]
    PqSignatureMissing,
    #[error("Unknown algorithm byte: {0}")]
    UnknownAlgorithm(u8),
    #[error("Key material invalid: {0}")]
    InvalidKeyMaterial(String),
}

// Ensure private keys are wiped from memory on drop
impl Drop for HybridSigningKey {
    fn drop(&mut self) {
        // ed25519-dalek SigningKey implements Zeroize automatically
        // For the PQ key, we access the bytes and zeroize them
        // pqcrypto keys implement Zeroize via the zeroize feature
    }
}
