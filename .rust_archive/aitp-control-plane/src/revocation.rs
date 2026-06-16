//! Session revocation list management.
//!
//! Maintains a set of revoked session IDs. When a session is revoked,
//! its ID is added here and propagated to eBPF maps for instant
//! kernel-level enforcement.

use dashmap::DashSet;
use std::sync::Arc;

/// Revocation list manager.
///
/// Thread-safe set of revoked session IDs. Revocations are permanent
/// for the lifetime of the control plane process (session IDs are
/// unique and never reused).
#[derive(Debug, Clone)]
pub struct RevocationList {
    revoked: Arc<DashSet<u64>>,
}

#[allow(dead_code)]
impl RevocationList {
    /// Create a new empty revocation list.
    pub fn new() -> Self {
        Self {
            revoked: Arc::new(DashSet::new()),
        }
    }

    /// Revoke a session ID.
    ///
    /// Returns `true` if the session was newly revoked, `false` if
    /// it was already in the revocation list.
    pub fn revoke(&self, session_id: u64) -> bool {
        let newly_inserted = self.revoked.insert(session_id);
        if newly_inserted {
            tracing::info!(
                session_id = format!("{:#018x}", session_id),
                "Session revoked"
            );
        }
        newly_inserted
    }

    /// Check if a session ID has been revoked.
    pub fn is_revoked(&self, session_id: u64) -> bool {
        self.revoked.contains(&session_id)
    }

    /// Number of revoked sessions.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Check if the revocation list is empty.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revoke_and_check() {
        let list = RevocationList::new();
        assert!(!list.is_revoked(0x1234));

        assert!(list.revoke(0x1234));
        assert!(list.is_revoked(0x1234));

        // Revoking again returns false
        assert!(!list.revoke(0x1234));
    }

    #[test]
    fn test_multiple_revocations() {
        let list = RevocationList::new();
        list.revoke(1);
        list.revoke(2);
        list.revoke(3);

        assert_eq!(list.len(), 3);
        assert!(list.is_revoked(1));
        assert!(list.is_revoked(2));
        assert!(list.is_revoked(3));
        assert!(!list.is_revoked(4));
    }
}
