use super::EnforcementPlane;
use dashmap::DashMap;

/// Session permit in the software enforcement map.
#[derive(Debug, Clone)]
struct SoftwarePermit {
    session_id: String,
    entity_id: String, // source entity
    source_ip: String,
    dest_ip: String,
    installed_at: i64,
}

/// Software-based enforcement — in-memory permit map.
/// Always available, no kernel dependencies.
pub struct SoftwareEnforcement {
    permits: DashMap<String, SoftwarePermit>, // session_id → permit
    entity_index: DashMap<String, Vec<String>>, // entity_id → [session_ids]
}

impl SoftwareEnforcement {
    pub fn new() -> Self {
        Self {
            permits: DashMap::new(),
            entity_index: DashMap::new(),
        }
    }
}

impl EnforcementPlane for SoftwareEnforcement {
    fn install_permit(&self, session_id: &str, source_ip: &str, dest_ip: &str) -> bool {
        let entity_id = source_ip.to_string(); // In real impl, would resolve to entity

        let permit = SoftwarePermit {
            session_id: session_id.to_string(),
            entity_id: entity_id.clone(),
            source_ip: source_ip.to_string(),
            dest_ip: dest_ip.to_string(),
            installed_at: chrono::Utc::now().timestamp(),
        };

        self.permits.insert(session_id.to_string(), permit);
        self.entity_index
            .entry(entity_id)
            .or_default()
            .push(session_id.to_string());

        tracing::debug!(
            "Software enforcement: permit installed for session {}",
            session_id
        );
        true
    }

    fn revoke_permit(&self, session_id: &str) -> bool {
        if let Some((_, permit)) = self.permits.remove(session_id) {
            // Remove from entity index
            if let Some(mut sessions) = self.entity_index.get_mut(&permit.entity_id) {
                sessions.retain(|s| s != session_id);
            }
            tracing::debug!(
                "Software enforcement: permit revoked for session {}",
                session_id
            );
            true
        } else {
            false
        }
    }

    fn revoke_all_for_entity(&self, entity_id: &str) -> u32 {
        let session_ids = self
            .entity_index
            .remove(entity_id)
            .map(|(_, ids)| ids)
            .unwrap_or_default();

        let count = session_ids.len() as u32;
        for sid in session_ids {
            self.permits.remove(&sid);
        }

        tracing::debug!(
            "Software enforcement: {} permits revoked for entity {}",
            count,
            entity_id
        );
        count
    }

    fn has_permit(&self, session_id: &str) -> bool {
        self.permits.contains_key(session_id)
    }

    fn name(&self) -> &'static str {
        "software"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_and_check() {
        let enforcement = SoftwareEnforcement::new();
        assert!(enforcement.install_permit("s1", "10.0.0.1", "10.0.0.2"));
        assert!(enforcement.has_permit("s1"));
        assert!(!enforcement.has_permit("s2"));
    }

    #[test]
    fn test_revoke() {
        let enforcement = SoftwareEnforcement::new();
        enforcement.install_permit("s1", "10.0.0.1", "10.0.0.2");
        assert!(enforcement.revoke_permit("s1"));
        assert!(!enforcement.has_permit("s1"));
        assert!(!enforcement.revoke_permit("s1")); // Already revoked
    }

    #[test]
    fn test_revoke_all_for_entity() {
        let enforcement = SoftwareEnforcement::new();
        enforcement.install_permit("s1", "10.0.0.1", "10.0.0.2");
        enforcement.install_permit("s2", "10.0.0.1", "10.0.0.3");
        enforcement.install_permit("s3", "10.0.0.5", "10.0.0.2"); // different entity

        let revoked = enforcement.revoke_all_for_entity("10.0.0.1");
        assert_eq!(revoked, 2);
        assert!(!enforcement.has_permit("s1"));
        assert!(!enforcement.has_permit("s2"));
        assert!(enforcement.has_permit("s3")); // Different entity, still active
    }
}
