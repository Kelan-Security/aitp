//! Identity registry for the AITP control plane.
//!
//! Provides thread-safe registration, lookup, and management of
//! AITP identities. Backed by `DashMap` for concurrent access.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use std::sync::Arc;
use thiserror::Error;

/// Errors in registry operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Entity not found.
    #[error("entity not found")]
    NotFound,
}

/// A registered identity in the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredIdentity {
    /// Entity ID (SHA-256 of public key).
    #[serde(with = "hex_bytes")]
    pub entity_id: [u8; 32],
    /// Ed25519 public key.
    #[serde(with = "hex_bytes")]
    pub public_key: [u8; 32],
    /// Human-readable name.
    pub name: String,
    /// Entity type.
    pub entity_type: String,
    /// Network addresses.
    pub addresses: Vec<String>,
    /// Registration timestamp (Unix seconds).
    pub registered_at: u64,
}

/// Thread-safe identity registry.
#[derive(Debug, Clone)]
pub struct IdentityRegistry {
    entries: Arc<DashMap<[u8; 32], RegisteredIdentity>>,
}

#[allow(dead_code)]
impl IdentityRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }

    /// Register an identity.
    pub fn register(&self, identity: RegisteredIdentity) {
        tracing::info!(
            name = %identity.name,
            entity_type = %identity.entity_type,
            "Identity registered"
        );
        self.entries.insert(identity.entity_id, identity);
    }

    /// Look up an identity by entity ID.
    pub fn resolve(&self, entity_id: &[u8; 32]) -> Result<RegisteredIdentity, RegistryError> {
        self.entries
            .get(entity_id)
            .map(|entry| entry.value().clone())
            .ok_or(RegistryError::NotFound)
    }

    /// Remove an identity.
    pub fn deregister(&self, entity_id: &[u8; 32]) -> bool {
        self.entries.remove(entity_id).is_some()
    }

    /// Number of registered identities.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Serde helper for [u8; 32] as hex strings.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<_, _>>()
            .map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}
