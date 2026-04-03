#[cfg(test)]
mod protocol_integration_tests {
    use crate::config::TransportConfig;
    use crate::session::SessionTable;
    use crate::header::{AitpHeader, IntentCode};
    use kelan_crypto::HybridSigningKey;
    use aitp_ai_engine::scorer::Verdict;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    
    use crate::transport::AitpTransport;

    #[tokio::test]
    async fn test_transport_basic_bind() {
        let config = TransportConfig::default();
        let transport = AitpTransport::bind(config).await.unwrap();
        let addr = transport.local_addr().unwrap();
        assert!(addr.is_ipv4());
        assert!(addr.port() > 0);
        assert!(transport.session_table().active_count().await == 0);
    }

    #[tokio::test]
    async fn test_session_table_smoke() {
        let sessions = Arc::new(SessionTable::new());
        let test_id = 0x123456789ABC_u64;
        assert!(sessions.get(test_id).await.is_none());
    }

    #[tokio::test]
    async fn test_header_intent_codes() {
        assert_eq!(IntentCode::from_u16(0x0001), IntentCode::ModelInference);
        assert_eq!(IntentCode::from_u16(0xFFFF), IntentCode::Unknown);
    }

    #[tokio::test]
    async fn test_crypto_key_generation() {
        let key1 = HybridSigningKey::generate();
        let key2 = HybridSigningKey::generate();
        assert_ne!(key1.verifying_key.entity_id(), key2.verifying_key.entity_id());
    }

    #[tokio::test]
    async fn test_verdict_enums() {
        assert_eq!(Verdict::from_score(10), Verdict::Deny);
        assert_eq!(Verdict::from_score(100), Verdict::Monitor);
        assert_eq!(Verdict::from_score(200), Verdict::Allow);
    }
}

