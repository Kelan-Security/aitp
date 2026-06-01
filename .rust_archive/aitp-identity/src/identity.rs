//! AITP Identity — Ed25519 keypair generation and entity ID derivation.
//!
//! Each AITP entity is identified by a 32-byte entity ID derived from
//! the SHA-256 hash of its Ed25519 public key. This provides a stable,
//! cryptographically bound identity that doesn't depend on IP addresses.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ────────────────────────── Errors ──────────────────────────

/// Errors in identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The provided public key bytes are invalid.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    /// The identity has expired.
    #[error("identity expired at timestamp {0}")]
    Expired(u64),
}

// ────────────────────────── Entity Type ──────────────────────────

/// The type of entity this identity represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    /// A human user.
    Human,
    /// An AI model or inference service.
    AiModel,
    /// A backend service or microservice.
    Service,
    /// A physical or virtual device.
    Device,
}

impl EntityType {
    /// String representation for serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::Human => "Human",
            EntityType::AiModel => "AiModel",
            EntityType::Service => "Service",
            EntityType::Device => "Device",
        }
    }
}

// ────────────────────────── Capability ──────────────────────────

/// A capability that an entity declares it supports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Can perform LLM inference.
    Inference,
    /// Can participate in multi-agent coordination.
    Coordination,
    /// Can transfer files.
    FileTransfer,
    /// Can relay data between entities.
    Relay,
    /// Custom capability string.
    Custom(String),
}

// ────────────────────────── Identity Metadata ──────────────────────────

/// Metadata associated with an AITP identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMetadata {
    /// Human-readable name for this entity.
    pub name: String,
    /// Type of entity.
    pub entity_type: EntityType,
    /// Capabilities this entity supports.
    pub capabilities: Vec<Capability>,
    /// Unix timestamp (seconds) when this identity was created.
    pub issued_at: u64,
    /// Optional expiry timestamp (seconds). `None` means no expiry.
    pub expires_at: Option<u64>,
}

// ────────────────────────── Hybrid Signature ──────────────────────────

/// A hybrid signature combining classical Ed25519 and ML-DSA-65 (Dilithium3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical 64-byte Ed25519 signature
    pub classical: Vec<u8>,
    /// Post-Quantum ML-DSA-65 detached signature
    pub pq: Vec<u8>,
}

// ────────────────────────── AITP Identity ──────────────────────────

/// A complete AITP identity containing a keypair and metadata.
///
/// The private key never leaves the node. The entity ID (SHA-256 of
/// the public keys) serves as the protocol-level address.
pub struct AitpIdentity {
    /// Ed25519 signing key (contains both private and public key).
    signing_key: SigningKey,
    /// ML-DSA-65 (Dilithium3) public key.
    pub pq_public_key: mldsa65::PublicKey,
    /// ML-DSA-65 (Dilithium3) secret key.
    pq_secret_key: mldsa65::SecretKey,
    /// The 32-byte entity ID: SHA-256(Ed25519_pubkey || ML-DSA_pubkey).
    pub entity_id: [u8; 32],
    /// Identity metadata.
    pub metadata: IdentityMetadata,
}

impl AitpIdentity {
    /// Generate a new identity with a fresh Ed25519 keypair.
    ///
    /// # Arguments
    ///
    /// * `name` — Human-readable name for this entity.
    /// * `entity_type` — The type of entity.
    /// * `capabilities` — Capabilities this entity supports.
    ///
    /// # Returns
    ///
    /// A new `AitpIdentity` with a random keypair and the entity ID
    /// derived from the public key hash.
    pub fn generate(
        name: impl Into<String>,
        entity_type: EntityType,
        capabilities: Vec<Capability>,
    ) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let (pq_public_key, pq_secret_key) = mldsa65::keypair();

        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        hasher.update(pq_public_key.as_bytes());
        let entity_id: [u8; 32] = hasher.finalize().into();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            signing_key,
            pq_public_key,
            pq_secret_key,
            entity_id,
            metadata: IdentityMetadata {
                name: name.into(),
                entity_type,
                capabilities,
                issued_at: now,
                expires_at: None,
            },
        }
    }

    /// Create an identity from an existing signing key.
    /// In a fully persistent PQ setup, we would also load the ML-DSA key.
    /// For this migration, we generate a fresh ML-DSA key for existing classical nodes.
    pub fn from_signing_key(
        signing_key: SigningKey,
        name: impl Into<String>,
        entity_type: EntityType,
        capabilities: Vec<Capability>,
    ) -> Self {
        let public_key = signing_key.verifying_key();
        let (pq_public_key, pq_secret_key) = mldsa65::keypair();

        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        hasher.update(pq_public_key.as_bytes());
        let entity_id: [u8; 32] = hasher.finalize().into();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            signing_key,
            pq_public_key,
            pq_secret_key,
            entity_id,
            metadata: IdentityMetadata {
                name: name.into(),
                entity_type,
                capabilities,
                issued_at: now,
                expires_at: None,
            },
        }
    }

    /// Get the Ed25519 public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Sign arbitrary data with this identity's private key.
    ///
    /// # Arguments
    ///
    /// * `data` — The bytes to sign.
    ///
    /// # Returns
    ///
    /// A 64-byte Ed25519 signature.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sig = self.signing_key.sign(data);
        sig.to_bytes()
    }

    /// Sign arbitrary data with both classical and post-quantum keys.
    pub fn sign_hybrid(&self, data: &[u8]) -> HybridSignature {
        let classical = self.sign(data).to_vec();
        let pq_sig = pqcrypto_mldsa::mldsa65::detached_sign(data, &self.pq_secret_key);
        HybridSignature {
            classical,
            pq: pq_sig.as_bytes().to_vec(),
        }
    }

    /// Verify a signature against this identity's public key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::VerificationFailed`] if the signature is invalid.
    pub fn verify(&self, data: &[u8], signature: &[u8; 64]) -> Result<(), IdentityError> {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.signing_key
            .verifying_key()
            .verify(data, &sig)
            .map_err(|e| IdentityError::VerificationFailed(e.to_string()))
    }

    /// Verify a hybrid signature.
    pub fn verify_hybrid(
        &self,
        data: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), IdentityError> {
        let classical_array = signature.classical.as_slice().try_into().map_err(|_| {
            IdentityError::VerificationFailed("invalid classical sig length".into())
        })?;
        self.verify(data, &classical_array)?;

        let pq_sig = pqcrypto_mldsa::mldsa65::DetachedSignature::from_bytes(&signature.pq)
            .map_err(|e| IdentityError::VerificationFailed(e.to_string()))?;
        pqcrypto_mldsa::mldsa65::verify_detached_signature(&pq_sig, data, &self.pq_public_key)
            .map_err(|e| IdentityError::VerificationFailed(e.to_string()))?;

        Ok(())
    }

    /// Compute the entity ID from public keys.
    ///
    /// Entity ID = SHA-256(Ed25519_public_key || ML-DSA_public_key)
    pub fn entity_id_from_pubkey(
        public_key: &[u8; 32],
        pq_public_key: &mldsa65::PublicKey,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.update(pq_public_key.as_bytes());
        hasher.finalize().into()
    }

    /// Check whether this identity has expired.
    ///
    /// Returns `true` if the identity has an expiry time and it has passed.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.metadata.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now > expires_at
        } else {
            false
        }
    }

    /// Get the age of this identity in seconds.
    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.metadata.issued_at)
    }
}

impl std::fmt::Debug for AitpIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AitpIdentity")
            .field("entity_id", &crate::identity::hex_short(&self.entity_id))
            .field("name", &self.metadata.name)
            .field("entity_type", &self.metadata.entity_type)
            .finish()
    }
}

/// Format bytes as short hex for debug output.
fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 4 {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    } else {
        let prefix: String = bytes[..4].iter().map(|b| format!("{b:02x}")).collect();
        format!("{prefix}...")
    }
}

/// Verify a classical signature using a raw public key.
/// Note: In Phase 7 this is only used for backward compatibility or simple hashes.
/// Full hybrid verification requires `verify_hybrid_with_pubkeys`.
pub fn verify_with_pubkey(
    public_key: &[u8; 32],
    data: &[u8],
    signature: &[u8; 64],
) -> Result<(), IdentityError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify(data, &sig)
        .map_err(|e| IdentityError::VerificationFailed(e.to_string()))
}

/// Verify a Hybrid Signature using raw public keys.
pub fn verify_hybrid_with_pubkeys(
    classical_pk: &[u8; 32],
    pq_pk: &pqcrypto_mldsa::mldsa65::PublicKey,
    data: &[u8],
    signature: &HybridSignature,
) -> Result<(), IdentityError> {
    let classical_array = signature.classical.as_slice().try_into().map_err(|_| {
        IdentityError::VerificationFailed("invalid classical signature length".into())
    })?;
    verify_with_pubkey(classical_pk, data, &classical_array)?;
    let pq_sig = pqcrypto_mldsa::mldsa65::DetachedSignature::from_bytes(&signature.pq)
        .map_err(|e| IdentityError::VerificationFailed(e.to_string()))?;
    pqcrypto_mldsa::mldsa65::verify_detached_signature(&pq_sig, data, pq_pk)
        .map_err(|e| IdentityError::VerificationFailed(e.to_string()))?;
    Ok(())
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = AitpIdentity::generate(
            "test-node",
            EntityType::Service,
            vec![Capability::Inference],
        );
        assert_eq!(id.metadata.name, "test-node");
        assert_eq!(id.metadata.entity_type, EntityType::Service);
        assert!(
            !id.entity_id.iter().all(|&b| b == 0),
            "Entity ID should not be all zeros"
        );
    }

    #[test]
    fn test_entity_id_derivation() {
        let id = AitpIdentity::generate("test", EntityType::AiModel, vec![]);
        let pubkey = id.public_key_bytes();
        let derived = AitpIdentity::entity_id_from_pubkey(&pubkey, &id.pq_public_key);
        assert_eq!(id.entity_id, derived);
    }

    #[test]
    fn test_sign_and_verify() {
        let id = AitpIdentity::generate("signer", EntityType::Human, vec![]);
        let data = b"test message for signing";
        let signature = id.sign(data);
        id.verify(data, &signature)
            .expect("Signature should be valid");
    }

    #[test]
    fn test_tampered_data_fails_verify() {
        let id = AitpIdentity::generate("signer", EntityType::Human, vec![]);
        let data = b"original message";
        let signature = id.sign(data);
        let result = id.verify(b"tampered message", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_pubkey() {
        let id = AitpIdentity::generate("node", EntityType::Service, vec![]);
        let data = b"verify with pubkey";
        let sig = id.sign(data);
        let pubkey = id.public_key_bytes();
        verify_with_pubkey(&pubkey, data, &sig).expect("Should verify");
    }

    #[test]
    fn test_different_identities_different_ids() {
        let id1 = AitpIdentity::generate("node-1", EntityType::Service, vec![]);
        let id2 = AitpIdentity::generate("node-2", EntityType::Service, vec![]);
        assert_ne!(id1.entity_id, id2.entity_id);
    }

    #[test]
    fn test_not_expired() {
        let id = AitpIdentity::generate("node", EntityType::Service, vec![]);
        assert!(!id.is_expired());
    }

    #[test]
    fn test_from_signing_key() {
        let key = SigningKey::generate(&mut OsRng);
        let id =
            AitpIdentity::from_signing_key(key.clone(), "from-key", EntityType::Device, vec![]);
        let expected_id =
            AitpIdentity::entity_id_from_pubkey(&key.verifying_key().to_bytes(), &id.pq_public_key);
        assert_eq!(id.entity_id, expected_id);
    }
}
