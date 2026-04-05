use aitp_core::header::IntentCode;
use kelan_crypto::HybridSigningKey;
use kelan_sdk::client::AitpClient;

#[tokio::test]
async fn test_real_5_phase_handshake() {
    // Skip in CI unless server is running
    let server_addr = match std::env::var(
        "KELAN_TEST_SERVER"
    ) {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!(
                "Skipping real handshake test \
                 (set KELAN_TEST_SERVER=host:port)"
            );
            return;
        }
    };

    let identity = HybridSigningKey::generate();

    let session = AitpClient::builder()
        .server(&server_addr)
        .intent(IntentCode::ModelInference)
        .identity(identity)
        .connect()
        .await
        .expect("Handshake must succeed");

    assert!(!session.session_id.is_nil());
    assert!(session.trust_score >= 0.0);
    assert!(
        session.verdict == "Allow" || 
        session.verdict == "Monitor",
        "Verdict must be Allow or Monitor, \
         got: {}", session.verdict
    );

    println!(
        "✓ Real handshake complete!\n\
         Session: {}\n\
         Score: {:.2}\n\
         Verdict: {}",
        session.session_id,
        session.trust_score,
        session.verdict
    );
}
