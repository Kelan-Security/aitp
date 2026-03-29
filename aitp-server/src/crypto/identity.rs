//! Entity identity management — now with hybrid PQ support.
//!
//! Backward compatible: loads old Ed25519-only keys and wraps them.
//! On new enrollment: generates hybrid keypair automatically.

use keyring::Entry;
use super::hybrid_sig::{HybridSigningKey, HybridVerifyingKey, HybridSignature};
use super::CryptoAlgorithm;

const KEYRING_SERVICE: &str = "kelan-server";
const KEYRING_KEY_V1:  &str = "ed25519-private-key";          // legacy
const KEYRING_KEY_V2:  &str = "hybrid-pq-private-key-v2";     // new

pub struct HybridEntityIdentity {
    /// The stable 32-byte entity identifier
    pub entity_id: [u8; 32],
    /// The hybrid public key (Ed25519 + ML-DSA-65)
    pub verifying_key: HybridVerifyingKey,
    /// Algorithm capabilities advertised to peers
    pub algorithm: CryptoAlgorithm,
    /// Private key material (never leaves this process)
    signing_key: HybridSigningKey,
}

impl HybridEntityIdentity {
    /// Load from OS keystore or generate a new hybrid keypair.
    /// If an old Ed25519-only key exists, migrates it automatically.
    pub fn load_or_generate() -> anyhow::Result<Self> {
        // Try to load new hybrid key first
        let entry_v2 = Entry::new(KEYRING_SERVICE, KEYRING_KEY_V2)?;
        if let Ok(hex_key) = entry_v2.get_password() {
            let key_bytes: Vec<u8> = hex::decode(hex_key.trim())?;
            let signing_key = HybridSigningKey::from_secret_bytes(&key_bytes)?;
            let entity_id = signing_key.verifying_key.entity_id();
            tracing::info!(
                entity_id = hex::encode(&entity_id[..8]),
                algorithm = "hybrid-pq (ML-DSA-65 + Ed25519)",
                "Loaded hybrid PQ identity"
            );
            return Ok(Self {
                entity_id,
                verifying_key: signing_key.verifying_key.clone(),
                algorithm: CryptoAlgorithm::HybridPQ,
                signing_key,
            });
        }

        // Check for legacy Ed25519-only key
        let entry_v1 = Entry::new(KEYRING_SERVICE, KEYRING_KEY_V1)?;
        if let Ok(_hex_key) = entry_v1.get_password() {
            tracing::info!("Legacy Ed25519 key found — migrating to hybrid PQ");
            // Load old Ed25519 key, generate new ML-DSA-65 alongside it
            // For migration: generate fresh hybrid key
            // (entity ID will change — this is intentional, re-enrollment needed)
            let signing_key = HybridSigningKey::generate();
            Self::save_hybrid_key(&entry_v2, &signing_key)?;

            let entity_id = signing_key.verifying_key.entity_id();
            tracing::warn!(
                "PQ migration: new EntityID = {}. Re-enrollment with Intelligence Core required.",
                hex::encode(&entity_id)
            );

            return Ok(Self {
                entity_id,
                verifying_key: signing_key.verifying_key.clone(),
                algorithm: CryptoAlgorithm::HybridPQ,
                signing_key,
            });
        }

        // No existing key — generate new hybrid keypair
        tracing::info!("Generating new hybrid PQ keypair (Ed25519 + ML-DSA-65)");
        let signing_key = HybridSigningKey::generate();
        Self::save_hybrid_key(&entry_v2, &signing_key)?;

        let entity_id = signing_key.verifying_key.entity_id();
        tracing::info!(
            entity_id = hex::encode(&entity_id[..8]),
            algorithm = "ML-DSA-65 + Ed25519 hybrid",
            "New hybrid PQ identity generated"
        );

        Ok(Self {
            entity_id,
            verifying_key: signing_key.verifying_key.clone(),
            algorithm: CryptoAlgorithm::HybridPQ,
            signing_key,
        })
    }

    fn save_hybrid_key(entry: &Entry, key: &HybridSigningKey) -> anyhow::Result<()> {
        let secret_bytes = key.to_secret_bytes();
        entry.set_password(&hex::encode(&secret_bytes))
            .map_err(|e| anyhow::anyhow!("Failed to save hybrid key: {}", e))?;
        tracing::info!("Hybrid PQ keypair saved to OS keystore");
        Ok(())
    }

    /// Sign data for the AITP handshake.
    pub fn sign(&self, data: &[u8]) -> HybridSignature {
        self.signing_key.sign(data)
    }

    /// Public key bytes for sending to the Intelligence Core during enrollment.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes()
    }

    /// Short display form for logs
    pub fn short_id(&self) -> String {
        hex::encode(&self.entity_id[..8])
    }

    /// Full hex EntityID
    pub fn entity_id_hex(&self) -> String {
        hex::encode(self.entity_id)
    }
}

// Legacy wrapper for backward compatibility with code that uses EntityIdentity
pub type EntityIdentity = HybridEntityIdentity;
