pub mod crypto;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    hybrid_sig::{verify_classical, verify_hybrid, HybridSignature, HybridVerifyingKey},
    CryptoAlgorithm,
};
use crate::protocol::AitpHeader;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey; // AitpHeaderV4 aliases this

// ────────────────────────── EntityIdentity ──────────────────────────

/// Represents a registered entity's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityIdentity {
    /// SHA-256(Ed25519 public key) — the unique EntityID.
    pub entity_id: String,
    /// Hex-encoded Ed25519 public key.
    pub public_key: String,
    /// Human-readable name.
    pub name: String,
    /// Entity type: workstation, server, service, ai_agent, iot
    pub entity_type: String,
    /// Department within the organisation.
    pub department: Option<String>,
    /// Clearance level: 0=unclassified, 1=CUI, 2=secret, 3=top_secret
    pub clearance_level: u8,
    /// Allowed intent codes (as string names).
    pub allowed_intents: Vec<String>,
    /// Whether this entity is quarantined.
    pub quarantined: bool,
}

// ────────────────────────── EntityRegistry ──────────────────────────

/// In-memory registry of known entities (backed by DB).
pub struct EntityRegistry {
    pub config: std::sync::Arc<crate::config::AppConfig>,
    entities: DashMap<String, EntityIdentity>,
}

impl EntityRegistry {
    pub fn new(config: std::sync::Arc<crate::config::AppConfig>) -> Self {
        Self {
            config,
            entities: DashMap::new(),
        }
    }

    /// Register an entity.
    pub fn register(&self, identity: EntityIdentity) {
        self.entities.insert(identity.entity_id.clone(), identity);
    }

    /// Look up an entity by ID.
    pub fn get(&self, entity_id: &str) -> Option<EntityIdentity> {
        self.entities.get(entity_id).map(|e| e.clone())
    }

    /// Check if an entity is registered.
    pub fn contains(&self, entity_id: &str) -> bool {
        self.entities.contains_key(entity_id)
    }

    /// Check if an entity is quarantined.
    pub fn is_quarantined(&self, entity_id: &str) -> bool {
        self.entities
            .get(entity_id)
            .map(|e| e.quarantined)
            .unwrap_or(false)
    }

    /// Quarantine an entity.
    pub fn quarantine(&self, entity_id: &str) -> bool {
        if let Some(mut e) = self.entities.get_mut(entity_id) {
            e.quarantined = true;
            true
        } else {
            false
        }
    }

    /// Release an entity from quarantine.
    pub fn release(&self, entity_id: &str) -> bool {
        if let Some(mut e) = self.entities.get_mut(entity_id) {
            e.quarantined = false;
            true
        } else {
            false
        }
    }

    /// Remove an entity from the registry.
    pub fn remove(&self, entity_id: &str) -> Option<EntityIdentity> {
        self.entities.remove(entity_id).map(|(_, v)| v)
    }

    /// Number of registered entities.
    pub fn count(&self) -> usize {
        self.entities.len()
    }

    /// Verify an incoming AITP packet signature.
    /// Handles both legacy Ed25519-only and new hybrid PQ clients.
    pub fn verify_packet_signature(
        &self,
        header: &AitpHeader,
        _entity: &EntityIdentity, // Using EntityIdentity mapping from earlier
    ) -> Result<(), CryptoVerifyError> {
        let payload = header.signing_payload();
        let algorithm = CryptoAlgorithm::from_byte(header.algorithm)
            .ok_or(CryptoVerifyError::UnknownAlgorithm(header.algorithm))?;

        // Check if this entity's algorithm satisfies server policy
        let policy = self.config.min_crypto_algorithm;
        if !algorithm.satisfies_policy(policy) {
            return Err(CryptoVerifyError::AlgorithmBelowPolicy {
                client: algorithm,
                required: policy,
            });
        }

        match algorithm {
            CryptoAlgorithm::Classical => {
                // Legacy Ed25519-only path
                if header.source_pk.len() != 32 {
                    return Err(CryptoVerifyError::InvalidKeyLength);
                }
                let pk_bytes: [u8; 32] = header
                    .source_pk
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoVerifyError::InvalidKeyLength)?;
                let vk = Ed25519VerifyingKey::from_bytes(&pk_bytes)
                    .map_err(|_| CryptoVerifyError::InvalidKey)?;
                let sig: [u8; 64] = header
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoVerifyError::InvalidSignatureLength)?;
                verify_classical(&vk, &payload, &sig)
                    .map_err(|_| CryptoVerifyError::VerificationFailed)?;
            }

            CryptoAlgorithm::HybridPQ | CryptoAlgorithm::PostQuantum => {
                // New hybrid PQ path — both algorithms must verify
                let vk = HybridVerifyingKey::from_bytes(&header.source_pk)
                    .ok_or(CryptoVerifyError::InvalidKey)?;
                let sig = HybridSignature::from_bytes(&header.signature)
                    .ok_or(CryptoVerifyError::InvalidSignatureLength)?;
                verify_hybrid(&vk, &payload, &sig)
                    .map_err(|_| CryptoVerifyError::VerificationFailed)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoVerifyError {
    #[error("Unknown algorithm byte: {0:#x}")]
    UnknownAlgorithm(u8),
    #[error("Client algorithm {client:?} below server policy {required:?}")]
    AlgorithmBelowPolicy {
        client: CryptoAlgorithm,
        required: CryptoAlgorithm,
    },
    #[error("Invalid public key material")]
    InvalidKey,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid signature length")]
    InvalidSignatureLength,
    #[error("Signature verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entity(id: &str) -> EntityIdentity {
        EntityIdentity {
            entity_id: id.to_string(),
            public_key: "deadbeef".to_string(),
            name: format!("entity-{}", id),
            entity_type: "workstation".to_string(),
            department: Some("Engineering".to_string()),
            clearance_level: 0,
            allowed_intents: vec!["ModelInference".into(), "Heartbeat".into()],
            quarantined: false,
        }
    }

    #[test]
    fn test_registry_crud() {
        let config = std::sync::Arc::new(crate::config::AppConfig::from_env());
        let reg = EntityRegistry::new(config);
        reg.register(make_entity("abc123"));
        assert!(reg.contains("abc123"));
        assert!(!reg.contains("xyz"));
        assert_eq!(reg.count(), 1);

        let e = reg.get("abc123").unwrap();
        assert_eq!(e.name, "entity-abc123");

        reg.remove("abc123");
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_quarantine() {
        let config = std::sync::Arc::new(crate::config::AppConfig::from_env());
        let reg = EntityRegistry::new(config);
        reg.register(make_entity("q1"));
        assert!(!reg.is_quarantined("q1"));

        assert!(reg.quarantine("q1"));
        assert!(reg.is_quarantined("q1"));

        assert!(reg.release("q1"));
        assert!(!reg.is_quarantined("q1"));

        assert!(!reg.quarantine("nonexistent"));
    }
}
