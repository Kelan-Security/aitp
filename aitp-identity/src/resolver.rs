//! Identity → IP resolution.
//!
//! Maps entity IDs (32-byte hashes) to network addresses.
//! Uses an in-memory HashMap for MVP. Redis backing planned for v0.2.
//!
//! Resolution must complete in < 1ms.

use std::collections::HashMap;
use std::net::SocketAddr;
use thiserror::Error;

/// Errors during identity resolution.
#[derive(Debug, Error)]
pub enum ResolverError {
    /// The requested entity ID was not found in the resolver.
    #[error("entity not found: {}", hex_short(entity_id))]
    NotFound { entity_id: [u8; 32] },

    /// Duplicate registration attempt.
    #[error("entity already registered: {}", hex_short(entity_id))]
    AlreadyRegistered { entity_id: [u8; 32] },
}

/// Information stored for a resolved identity.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// Entity ID (SHA-256 of public key).
    pub entity_id: [u8; 32],
    /// Ed25519 public key bytes.
    pub public_key: [u8; 32],
    /// Network addresses this entity can be reached at.
    pub addresses: Vec<SocketAddr>,
}

/// In-memory identity resolver.
///
/// Maps entity IDs to their network addresses. Designed for
/// single-node MVP use. For multi-node deployments, this will
/// be backed by Redis or a distributed store.
///
/// # Performance
///
/// All operations complete in O(1) average time (HashMap).
/// Lookup latency target: < 1ms.
#[derive(Debug, Default)]
pub struct IdentityResolver {
    /// entity_id → ResolvedIdentity
    store: HashMap<[u8; 32], ResolvedIdentity>,
}

impl IdentityResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    /// Register an identity with its network addresses.
    ///
    /// # Arguments
    ///
    /// * `entity_id` — The 32-byte entity ID.
    /// * `public_key` — The 32-byte Ed25519 public key.
    /// * `addresses` — Network addresses where this entity can be reached.
    ///
    /// If the entity is already registered, the entry is updated (upsert).
    pub fn register(
        &mut self,
        entity_id: [u8; 32],
        public_key: [u8; 32],
        addresses: Vec<SocketAddr>,
    ) {
        self.store.insert(
            entity_id,
            ResolvedIdentity {
                entity_id,
                public_key,
                addresses,
            },
        );
    }

    /// Resolve an entity ID to its network information.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError::NotFound`] if the entity is not registered.
    pub fn resolve(&self, entity_id: &[u8; 32]) -> Result<&ResolvedIdentity, ResolverError> {
        self.store.get(entity_id).ok_or(ResolverError::NotFound {
            entity_id: *entity_id,
        })
    }

    /// Resolve an entity ID to its socket addresses.
    ///
    /// Convenience method that returns just the addresses.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError::NotFound`] if the entity is not registered.
    pub fn resolve_addrs(&self, entity_id: &[u8; 32]) -> Result<&[SocketAddr], ResolverError> {
        self.resolve(entity_id)
            .map(|resolved| resolved.addresses.as_slice())
    }

    /// Remove an identity from the resolver.
    ///
    /// Returns `true` if the identity was found and removed.
    pub fn deregister(&mut self, entity_id: &[u8; 32]) -> bool {
        self.store.remove(entity_id).is_some()
    }

    /// Get the number of registered identities.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Check if the resolver is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

/// Format a byte array as a short hex string for error messages.
fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "..."
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn test_register_and_resolve() {
        let mut resolver = IdentityResolver::new();
        let id = [0xAA; 32];
        let pk = [0xBB; 32];
        resolver.register(id, pk, vec![addr(9999)]);

        let resolved = resolver.resolve(&id).unwrap();
        assert_eq!(resolved.entity_id, id);
        assert_eq!(resolved.public_key, pk);
        assert_eq!(resolved.addresses.len(), 1);
    }

    #[test]
    fn test_resolve_not_found() {
        let resolver = IdentityResolver::new();
        let id = [0xFF; 32];
        assert!(resolver.resolve(&id).is_err());
    }

    #[test]
    fn test_resolve_addrs() {
        let mut resolver = IdentityResolver::new();
        let id = [0x11; 32];
        resolver.register(id, [0x22; 32], vec![addr(8000), addr(8001)]);

        let addrs = resolver.resolve_addrs(&id).unwrap();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_deregister() {
        let mut resolver = IdentityResolver::new();
        let id = [0x33; 32];
        resolver.register(id, [0x44; 32], vec![addr(7000)]);
        assert_eq!(resolver.len(), 1);

        assert!(resolver.deregister(&id));
        assert_eq!(resolver.len(), 0);
        assert!(resolver.resolve(&id).is_err());
    }

    #[test]
    fn test_upsert_overwrites() {
        let mut resolver = IdentityResolver::new();
        let id = [0x55; 32];
        resolver.register(id, [0x66; 32], vec![addr(5000)]);
        resolver.register(id, [0x77; 32], vec![addr(5001), addr(5002)]);

        assert_eq!(resolver.len(), 1);
        let resolved = resolver.resolve(&id).unwrap();
        assert_eq!(resolved.public_key, [0x77; 32]);
        assert_eq!(resolved.addresses.len(), 2);
    }

    #[test]
    fn test_multi_region_mapping() {
        let mut resolver = IdentityResolver::new();
        let id = [0x88; 32];
        let addrs = vec![
            addr(9000), // US-East
            addr(9001), // EU-West
            addr(9002), // AP-Southeast
        ];
        resolver.register(id, [0x99; 32], addrs);

        let resolved_addrs = resolver.resolve_addrs(&id).unwrap();
        assert_eq!(resolved_addrs.len(), 3);
    }
}
