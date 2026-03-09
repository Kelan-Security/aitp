pub mod crypto;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

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
    entities: DashMap<String, EntityIdentity>,
}

impl EntityRegistry {
    pub fn new() -> Self {
        Self {
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
        let reg = EntityRegistry::new();
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
        let reg = EntityRegistry::new();
        reg.register(make_entity("q1"));
        assert!(!reg.is_quarantined("q1"));

        assert!(reg.quarantine("q1"));
        assert!(reg.is_quarantined("q1"));

        assert!(reg.release("q1"));
        assert!(!reg.is_quarantined("q1"));

        assert!(!reg.quarantine("nonexistent"));
    }
}
