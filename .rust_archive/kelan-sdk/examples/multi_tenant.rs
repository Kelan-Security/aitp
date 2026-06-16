use kelan_sdk::{AitpClient, KelanServer, IntentCode};
use kelan_crypto::HybridSigningKey;

#[tokio::main]
async fn main() -> Result<(), kelan_sdk::SdkError> {
    tokio::spawn(async {
        let _ = KelanServer::builder()
            .on_session(|session| async move {
                println!(
                    "[Server] Handled session {}, verdict: {:?}",
                    session.session_id,
                    session.verdict
                );
                Ok(())
            })
            .build()
            .await
            .unwrap()
            .run()
            .await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let identity_a = HybridSigningKey::generate();
    let _session_a = AitpClient::builder()
        .server("127.0.0.1:9999")
        .intent(IntentCode::ModelInference)
        .identity(identity_a)
        .connect()
        .await?;
    println!("[Tenant A] Inference session established.");

    let identity_b = HybridSigningKey::generate();
    let _session_b = AitpClient::builder()
        .server("127.0.0.1:9999")
        .intent(IntentCode::Telemetry)
        .identity(identity_b)
        .connect()
        .await?;
    println!("[Tenant B] Telemetry session established.");

    Ok(())
}
