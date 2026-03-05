use aitp_core::handshake::{
    HandshakeConfig, HandshakeMachine, HandshakeMessage, HandshakeMessageKind,
};
use aitp_core::header::IntentCode;
use std::time::Instant;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_load_handshake_state_machine_concurrency_1000() {
    let start = Instant::now();
    let num_sessions = 1000;
    let config = HandshakeConfig::default();

    println!("Starting 1000 concurrent state machine simulations...");

    let mut machines = Vec::with_capacity(num_sessions);
    for i in 0..num_sessions {
        machines.push(HandshakeMachine::new(i as u64, false, config.clone()));
    }

    for machine in machines.iter_mut() {
        let msg = HandshakeMessage {
            kind: HandshakeMessageKind::Hello,
            source_id: [0u8; 32],
            dest_id: [0u8; 32],
            session_id: machine.session_id(),
            intent: IntentCode::ModelInference,
            trust_score: 0,
            challenge_nonce: None,
            payload: vec![],
        };

        machine.on_message(&msg).unwrap();
    }

    let elapsed = start.elapsed();
    let num_sessions_u32 = num_sessions as u32;
    println!(
        "Processed 1000 HELLO state transitions in {:?}. Average latency: {:?}",
        elapsed,
        elapsed / num_sessions_u32
    );

    assert!(
        elapsed.as_secs() < 1,
        "State machine transitions too slow: {:?}",
        elapsed
    );
}
