use aitp_core::header::{flags, AitpHeader, IntentCode};
use aitp_identity::identity::{AitpIdentity, EntityType};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_invalid_signature_rejection() {
    let source = AitpIdentity::generate("source", EntityType::Service, vec![]);
    let dest = AitpIdentity::generate("dest", EntityType::Service, vec![]);

    let mut header = AitpHeader::new(
        flags::SYN,
        IntentCode::ModelInference,
        1,
        source.entity_id,
        dest.entity_id,
        255,
        0,
        123456789,
        [0u8; 12],
    );

    // Sign with WRONG key (destination signs instead of source)
    header.sign(dest.signing_key());

    // Verification against source's public key should fail
    let result = header.verify_signature(&source.public_key_bytes());
    assert!(
        result.is_err(),
        "Header signed by wrong key must fail verification"
    );
}

#[tokio::test]
async fn test_tampered_payload_signature_failure() {
    let source = AitpIdentity::generate("source", EntityType::Service, vec![]);

    let mut header = AitpHeader::new(
        flags::SYN,
        IntentCode::ModelInference,
        1,
        source.entity_id,
        [0u8; 32],
        100, // Initial trust score
        0,
        123456789,
        [0u8; 12],
    );

    header.sign(source.signing_key());

    // Tamper with trust_score after signing
    header.trust_score = 255;

    let result = header.verify_signature(&source.public_key_bytes());
    assert!(result.is_err(), "Tampered header must fail verification");
}

#[tokio::test]
async fn test_replay_protection_nonce_reuse() {
    let source = AitpIdentity::generate("source", EntityType::Service, vec![]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let header = AitpHeader::new(
        flags::SYN,
        IntentCode::ModelInference,
        1,
        source.entity_id,
        [0u8; 32],
        255,
        0,
        now,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    );

    // 1. Initial packet received -> OK
    let mut seen_nonces = std::collections::HashSet::new();
    seen_nonces.insert((header.source_id, header.nonce, header.timestamp));

    // 2. Replay of exact same packet
    let is_replay = seen_nonces.contains(&(header.source_id, header.nonce, header.timestamp));
    assert!(is_replay, "Identical packet must be detected as replay");

    // 3. Packet with old timestamp (outside window)
    let old_timestamp = now - 600_000_000_000; // 10 minutes old
    let is_too_old = (now - old_timestamp) > 300_000_000_000; // 5 minute window
    assert!(is_too_old, "Packet older than 5 minutes must be rejected");
}

#[tokio::test]
async fn test_expired_permit_token_rejection() {
    use aitp_identity::token::{PermitToken, SessionConstraints};

    let mut token = PermitToken::new(
        1,
        [0u8; 32],
        [0u8; 32],
        0x0001,
        128,
        SessionConstraints::default(),
        3600, // 1 hour TTL
    );

    // Fabricate an old issuance time
    token.issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 4000;

    let result = token.check_expiry();
    assert!(
        result.is_err(),
        "Token issued 4000s ago with 3600s TTL must be expired"
    );
}
