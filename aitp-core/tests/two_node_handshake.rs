//! AITP v0.1 Integration Test — Two-Node Full Handshake + Data Transfer
//!
//! This is the **definitive v0.1 done** test. It verifies:
//! 1. Two AITP nodes can start on separate ports
//! 2. Handshake completes (SYN → trust eval → SYN+ACK → session established)
//! 3. Data payload is transmitted and received correctly
//! 4. Trust score in received packet is > 0 (Allow verdict)
//! 5. Total handshake completes in < 100ms
//! 6. REVOKE terminates the session
//! 7. Subsequent DATA packets on a revoked session are dropped

use aitp_ai_engine::engine::TrustEngine;
use aitp_core::framing::AitpPacket;
use aitp_core::header::{flags, AitpHeader, IntentCode};
use aitp_core::transport::{AitpTransport, TransportConfig, TransportEvent};
use aitp_identity::identity::{AitpIdentity, Capability, EntityType};
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::time::{Duration, Instant};

// ────────────────────────── Helpers ──────────────────────────

fn rand_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// ────────────────────────── The Integration Test ──────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_full_two_node_handshake_and_data_transfer() {
    // ── Setup: create two distinct identities ──
    let identity_a = Arc::new(AitpIdentity::generate(
        "node-alpha",
        EntityType::AiModel,
        vec![Capability::Inference, Capability::Coordination],
    ));
    let identity_b = Arc::new(AitpIdentity::generate(
        "node-beta",
        EntityType::Service,
        vec![Capability::Inference, Capability::Coordination],
    ));

    let trust_engine_a = Arc::new(TrustEngine::with_defaults());
    let trust_engine_b = Arc::new(TrustEngine::with_defaults());

    // ── Step 1: Spawn Node A (port 9997) and Node B (port 9998) ──
    let config_a = TransportConfig {
        bind_addr: "127.0.0.1:9997".parse().unwrap(),
        max_sessions: 1024,
        max_datagram_size: 65535,
    };
    let config_b = TransportConfig {
        bind_addr: "127.0.0.1:9998".parse().unwrap(),
        max_sessions: 1024,
        max_datagram_size: 65535,
    };

    let (transport_a, _events_a) =
        AitpTransport::bind_with_coordinator(config_a, identity_a.clone(), trust_engine_a)
            .await
            .expect("Failed to bind Node A");

    let (transport_b, mut events_b) =
        AitpTransport::bind_with_coordinator(config_b, identity_b.clone(), trust_engine_b)
            .await
            .expect("Failed to bind Node B");

    let addr_a = transport_a.local_addr().unwrap();
    let addr_b = transport_b.local_addr().unwrap();

    eprintln!("Node A bound to {addr_a}");
    eprintln!("Node B bound to {addr_b}");

    let transport_a = Arc::new(transport_a);
    let transport_b = Arc::new(transport_b);

    // Spawn receive loops for both nodes
    let ta = transport_a.clone();
    let task_a = tokio::spawn(async move { ta.run().await });

    let tb = transport_b.clone();
    let task_b = tokio::spawn(async move { tb.run().await });

    // ── Step 2: Node A initiates connection to Node B ──
    let handshake_start = Instant::now();
    let session_id: u64 = 0xA17B_0001_0001;

    // Build and sign SYN packet
    let mut syn_header = AitpHeader::new(
        flags::SYN,
        IntentCode::ModelInference,
        session_id,
        identity_a.entity_id,
        identity_b.entity_id,
        0, // trust score 0 (not yet evaluated)
        0, // no payload
        now_nanos(),
        rand_nonce(),
    );
    syn_header.sign(identity_a.signing_key());

    let syn_packet = AitpPacket::new(syn_header, vec![]).expect("Failed to create SYN packet");

    transport_a
        .send_packet(&syn_packet, addr_b)
        .await
        .expect("Failed to send SYN");

    eprintln!("Node A → Node B: SYN sent (session {session_id:#018x})");

    // ── Step 3: Wait for Node B to emit SessionEstablished ──
    let event_b = tokio::time::timeout(Duration::from_secs(5), events_b.recv())
        .await
        .expect("Timeout waiting for Node B SessionEstablished")
        .expect("Node B event channel closed");

    let (established_trust_score, _peer_entity_id) = match event_b {
        TransportEvent::SessionEstablished {
            session_id: sid,
            trust_score,
            peer_entity_id,
            intent,
            ..
        } => {
            assert_eq!(sid, session_id, "Session ID mismatch on Node B");
            assert_eq!(intent, IntentCode::ModelInference, "Intent mismatch");
            assert_eq!(
                peer_entity_id, identity_a.entity_id,
                "Peer entity ID mismatch"
            );
            eprintln!("Node B: session established (trust_score={trust_score}, intent={intent})");
            (trust_score, peer_entity_id)
        }
        other => panic!("Expected SessionEstablished on Node B, got: {other:?}"),
    };

    let handshake_elapsed = handshake_start.elapsed();
    eprintln!("Handshake completed in {handshake_elapsed:?}");

    // ── Step 4: Verify trust score > 0 (Allow verdict) ──
    assert!(
        established_trust_score > 0,
        "Trust score should be > 0 for Allow verdict, got {established_trust_score}"
    );
    eprintln!("✓ Trust score = {established_trust_score} (> 0, ALLOW)");

    // ── Step 5: Assert handshake time < 100ms ──
    assert!(
        handshake_elapsed < Duration::from_millis(100),
        "Handshake took {handshake_elapsed:?} — must be < 100ms"
    );
    eprintln!("✓ Handshake time = {handshake_elapsed:?} (< 100ms)");

    // ── Step 6: Verify session is in Node B's table ──
    assert!(
        transport_b.session_table().contains(session_id),
        "Session should be in Node B's session table"
    );
    eprintln!("✓ Session {session_id:#018x} is in Node B's session table");

    // ── Step 7: Node A sends data payload to Node B ──
    let test_payload = b"AITP_INTEGRATION_TEST_PAYLOAD_v0.2".to_vec();
    let payload_len = test_payload.len() as u16;

    let mut data_header = AitpHeader::new(
        0, // No flags (DATA)
        IntentCode::DataSync,
        session_id,
        identity_a.entity_id,
        identity_b.entity_id,
        0,
        payload_len,
        now_nanos(),
        rand_nonce(),
    );
    data_header.sign(identity_a.signing_key());

    let data_packet =
        AitpPacket::new(data_header, test_payload.clone()).expect("Failed to create DATA packet");

    transport_a
        .send_packet(&data_packet, addr_b)
        .await
        .expect("Failed to send DATA");

    eprintln!("Node A → Node B: DATA sent ({payload_len} bytes)");

    // ── Step 8: Verify Node B receives the payload ──
    let data_event = tokio::time::timeout(Duration::from_secs(5), events_b.recv())
        .await
        .expect("Timeout waiting for DataReceived on Node B")
        .expect("Node B event channel closed");

    match data_event {
        TransportEvent::DataReceived {
            session_id: sid,
            payload,
            header,
            ..
        } => {
            assert_eq!(sid, session_id, "Data session ID mismatch");
            assert_eq!(
                payload, b"AITP_INTEGRATION_TEST_PAYLOAD_v0.2",
                "Payload content mismatch"
            );
            assert_eq!(header.intent_code, IntentCode::DataSync);
            eprintln!(
                "✓ Node B received payload: {:?} ({} bytes)",
                String::from_utf8_lossy(&payload),
                payload.len()
            );
        }
        other => panic!("Expected DataReceived on Node B, got: {other:?}"),
    }

    // ── Step 9: Node A sends REVOKE ──
    let mut revoke_header = AitpHeader::new(
        flags::REVOKE,
        IntentCode::ControlSignal,
        session_id,
        identity_a.entity_id,
        identity_b.entity_id,
        0,
        0,
        now_nanos(),
        rand_nonce(),
    );
    revoke_header.sign(identity_a.signing_key());

    let revoke_packet =
        AitpPacket::new(revoke_header, vec![]).expect("Failed to create REVOKE packet");

    transport_a
        .send_packet(&revoke_packet, addr_b)
        .await
        .expect("Failed to send REVOKE");

    eprintln!("Node A → Node B: REVOKE sent");

    // ── Step 10: Verify Node B processes the REVOKE ──
    let revoke_event = tokio::time::timeout(Duration::from_secs(5), events_b.recv())
        .await
        .expect("Timeout waiting for SessionRevoked on Node B")
        .expect("Node B event channel closed");

    match revoke_event {
        TransportEvent::SessionRevoked {
            session_id: sid, ..
        } => {
            assert_eq!(sid, session_id, "Revoke session ID mismatch");
            eprintln!("✓ Node B received REVOKE for session {session_id:#018x}");
        }
        other => panic!("Expected SessionRevoked on Node B, got: {other:?}"),
    }

    // ── Step 11: Verify session removed from Node B's table ──
    assert!(
        !transport_b.session_table().contains(session_id),
        "Session should be removed from Node B's table after REVOKE"
    );
    eprintln!("✓ Session {session_id:#018x} removed from Node B's session table");

    // ── Step 12: Send DATA after REVOKE → must be dropped as orphan ──
    let mut post_revoke_header = AitpHeader::new(
        0,
        IntentCode::DataSync,
        session_id,
        identity_a.entity_id,
        identity_b.entity_id,
        0,
        5,
        now_nanos(),
        rand_nonce(),
    );
    post_revoke_header.sign(identity_a.signing_key());

    let post_revoke_pkt = AitpPacket::new(post_revoke_header, b"GHOST".to_vec())
        .expect("Failed to create post-revoke packet");

    transport_a
        .send_packet(&post_revoke_pkt, addr_b)
        .await
        .expect("Failed to send post-revoke DATA");

    eprintln!("Node A → Node B: DATA sent after REVOKE (should be dropped)");

    // The next event should be a PacketDropped (orphan packet)
    let drop_event = tokio::time::timeout(Duration::from_secs(5), events_b.recv())
        .await
        .expect("Timeout waiting for PacketDropped on Node B")
        .expect("Node B event channel closed");

    match drop_event {
        TransportEvent::PacketDropped { reason, .. } => {
            assert!(
                reason.contains("orphan"),
                "Drop reason should mention 'orphan', got: {reason}"
            );
            eprintln!("✓ Post-revoke DATA correctly dropped: {reason}");
        }
        other => panic!("Expected PacketDropped on Node B, got: {other:?}"),
    }

    // ── Verify total session data transfer stats on Node B ──
    // The session is already removed, so we can't check stats directly,
    // but the fact that DataReceived fired with correct payload proves it.

    // ── Cleanup ──
    task_a.abort();
    task_b.abort();

    eprintln!();
    eprintln!("═══════════════════════════════════════════");
    eprintln!("  AITP v0.1 INTEGRATION TEST PASSED ✓");
    eprintln!("  Handshake:    {handshake_elapsed:?}");
    eprintln!("  Trust Score:  {established_trust_score}");
    eprintln!("  Payload:      AITP_INTEGRATION_TEST_PAYLOAD_v0.2");
    eprintln!("  Revocation:   Verified");
    eprintln!("  Post-revoke:  Correctly rejected");
    eprintln!("═══════════════════════════════════════════");
}

/// Verify that two nodes can establish sessions independently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_sessions() {
    let id_a = Arc::new(AitpIdentity::generate(
        "node-a",
        EntityType::Service,
        vec![Capability::Inference],
    ));
    let id_b = Arc::new(AitpIdentity::generate(
        "node-b",
        EntityType::Service,
        vec![Capability::Inference],
    ));
    let trust = Arc::new(TrustEngine::with_defaults());

    let (transport_b, mut events_b) = AitpTransport::bind_with_coordinator(
        TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
        id_b.clone(),
        trust.clone(),
    )
    .await
    .unwrap();

    let addr_b = transport_b.local_addr().unwrap();
    let transport_b = Arc::new(transport_b);
    let tb = transport_b.clone();
    let task_b = tokio::spawn(async move { tb.run().await });

    // Create a raw client socket (not a full transport)
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send 3 SYNs with different session IDs in quick succession
    let session_ids: Vec<u64> = vec![0x1001, 0x1002, 0x1003];

    for &sid in &session_ids {
        let mut syn = AitpHeader::new(
            flags::SYN,
            IntentCode::ModelInference,
            sid,
            id_a.entity_id,
            id_b.entity_id,
            0,
            0,
            now_nanos(),
            rand_nonce(),
        );
        syn.sign(id_a.signing_key());
        let pkt = AitpPacket::new(syn, vec![]).unwrap();
        client_socket
            .send_to(&pkt.to_bytes(), addr_b)
            .await
            .unwrap();
    }

    // Collect 3 SessionEstablished events
    let mut established = Vec::new();
    for _ in 0..3 {
        let event = tokio::time::timeout(Duration::from_secs(5), events_b.recv())
            .await
            .expect("Timeout waiting for session")
            .expect("Channel closed");

        if let TransportEvent::SessionEstablished { session_id, .. } = event {
            established.push(session_id);
        }
    }

    established.sort();
    assert_eq!(established, vec![0x1001, 0x1002, 0x1003]);
    assert_eq!(transport_b.session_table().len(), 3);

    task_b.abort();
}

/// Verify that a FIN gracefully closes a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_fin_closes_session() {
    let id_a = Arc::new(AitpIdentity::generate(
        "fin-sender",
        EntityType::Service,
        vec![],
    ));
    let id_b = Arc::new(AitpIdentity::generate(
        "fin-receiver",
        EntityType::Service,
        vec![],
    ));
    let trust = Arc::new(TrustEngine::with_defaults());

    let (transport_b, mut events_b) = AitpTransport::bind_with_coordinator(
        TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
        id_b.clone(),
        trust.clone(),
    )
    .await
    .unwrap();

    let addr_b = transport_b.local_addr().unwrap();
    let transport_b = Arc::new(transport_b);
    let tb = transport_b.clone();
    let task_b = tokio::spawn(async move { tb.run().await });

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let session_id: u64 = 0xF100;

    // SYN
    let mut syn = AitpHeader::new(
        flags::SYN,
        IntentCode::DataSync,
        session_id,
        id_a.entity_id,
        id_b.entity_id,
        0,
        0,
        now_nanos(),
        rand_nonce(),
    );
    syn.sign(id_a.signing_key());
    client
        .send_to(&AitpPacket::new(syn, vec![]).unwrap().to_bytes(), addr_b)
        .await
        .unwrap();

    // Wait for established
    let event = tokio::time::timeout(Duration::from_secs(5), events_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, TransportEvent::SessionEstablished { .. }));
    assert!(transport_b.session_table().contains(session_id));

    // FIN
    let mut fin = AitpHeader::new(
        flags::FIN,
        IntentCode::ControlSignal,
        session_id,
        id_a.entity_id,
        id_b.entity_id,
        0,
        0,
        now_nanos(),
        rand_nonce(),
    );
    fin.sign(id_a.signing_key());
    client
        .send_to(&AitpPacket::new(fin, vec![]).unwrap().to_bytes(), addr_b)
        .await
        .unwrap();

    // Wait for SessionClosed
    let event = tokio::time::timeout(Duration::from_secs(5), events_b.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        TransportEvent::SessionClosed {
            session_id: sid, ..
        } => {
            assert_eq!(sid, session_id);
        }
        other => panic!("Expected SessionClosed, got {other:?}"),
    }

    // Session should be removed
    assert!(!transport_b.session_table().contains(session_id));

    task_b.abort();
}
