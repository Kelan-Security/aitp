// Integration tests — external crate context
// DO NOT use crate:: here, use aitp_core::

use aitp_core::transport::{TransportConfig, AitpTransport};
use aitp_core::session::SessionTable;
use aitp_core::header::IntentCode;
use kelan_crypto::HybridSigningKey;
use aitp_ai_engine::scorer::Verdict;
use std::sync::Arc;

// REMOVED: use crate::header::AitpHeader — unused
// REMOVED: use tokio::net::UdpSocket — unused

#[tokio::test]
async fn test_transport_basic_bind() {
    let config = TransportConfig::default();
    
    let transport: AitpTransport =
        AitpTransport::bind(config).await
        .expect("Transport must bind successfully");
    
    let addr = transport.local_addr()
        .expect("Must have local address after bind");
    
    assert!(addr.is_ipv4());
    assert!(addr.port() > 0);
    assert_eq!(
        transport.session_table().len(),
        0
    );
}

#[tokio::test]
async fn test_session_table_smoke() {
    let sessions = Arc::new(SessionTable::new(100));
    let test_id: u64 = 0x123456789ABC;
    
    let result: Option<_> = sessions.get(test_id);
    assert!(result.is_none());
}

#[tokio::test]
async fn test_header_intent_codes() {
    assert_eq!(
        IntentCode::from_u16(0x0001),
        IntentCode::ModelInference
    );
    assert_eq!(
        IntentCode::from_u16(0xFFFF),
        IntentCode::Unknown
    );
}

#[tokio::test]
async fn test_crypto_key_generation() {
    let key1 = HybridSigningKey::generate();
    let key2 = HybridSigningKey::generate();
    assert_ne!(
        key1.verifying_key.entity_id(),
        key2.verifying_key.entity_id()
    );
}

#[tokio::test]
async fn test_verdict_enums() {
    assert_eq!(Verdict::from_score(10), Verdict::Deny);
    assert_eq!(Verdict::from_score(100), Verdict::Monitor);
    assert_eq!(Verdict::from_score(200), Verdict::Allow);
}

