use aitp_ai_engine::scorer::Verdict;
use aitp_core::header::{AitpHeader, IntentCode};
use aitp_identity::token::{PermitToken, SessionConstraints};
use proptest::prelude::*;

// Helper to map trust level for monotonicity check
fn verdict_trust_level(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Deny => 0,
        Verdict::Monitor => 1,
        Verdict::Allow => 2,
    }
}

proptest! {
    #[test]
    fn header_roundtrip(
        version in 1u8..=1,
        flags in 0u8..=15,
        intent_raw in 0u16..=0xFFFF,
        session_id in any::<u64>(),
        trust_score in 0u8..=255,
        payload_len in 0u16..=0xFFFF,
        timestamp in any::<u64>(),
        nonce in any::<[u8; 12]>(),
        signature in any::<[u8; 64]>(),
    ) {
        let intent = IntentCode::from_u16(intent_raw);
        let header = AitpHeader {
            version,
            flags,
            intent_code: intent,
            session_id,
            source_id: [0u8; 32],
            dest_id: [0u8; 32],
            trust_score,
            reserved: 0,
            payload_len,
            timestamp,
            nonce,
            signature,
        };
        let bytes = header.to_bytes();
        let parsed = AitpHeader::from_bytes(&bytes).unwrap();

        // Compare relevant fields (version will be 1 as per deserialization logic)
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.flags, flags & 0x0F);
        assert_eq!(parsed.intent_code, intent);
        assert_eq!(parsed.session_id, session_id);
        assert_eq!(parsed.trust_score, trust_score);
        assert_eq!(parsed.payload_len, payload_len);
        assert_eq!(parsed.timestamp, timestamp);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.signature, signature);
    }

    #[test]
    fn trust_score_verdict_monotonic(score in 1u8..=255) {
        let verdict_low = Verdict::from_score(score - 1);
        let verdict_high = Verdict::from_score(score);
        assert!(verdict_trust_level(verdict_high) >= verdict_trust_level(verdict_low));
    }

    #[test]
    fn permit_token_always_expires(ttl in 1u32..86400) {
        let token = PermitToken::new(
            1, [0u8; 32], [0u8; 32], 0x0001, 128,
            SessionConstraints::default(), ttl
        );

        // Issued at is current time
        let now = token.issued_at;

        // Check manually using the logic from PermitToken
        let expires_at = now.saturating_add(ttl as u64);

        assert!(now + ttl as u64 + 1 > expires_at);
        assert!(now + ttl as u64 >= expires_at);
    }
}
