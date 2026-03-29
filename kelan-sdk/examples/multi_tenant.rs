use kelan_sdk::{IntentCode, KelanClient, KelanServer};
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<(), kelan_sdk::KelanError> {
    // Start Server
    tokio::spawn(async {
        let _ = KelanServer::builder()
            .on_session(|session| async move {
                println!(
                    "[Server] Handled session {}, verdict: {:?}",
                    session.session_id(),
                    session.trust_result().verdict
                );
                session.send(b"tenant approved").await?;
                Ok(())
            })
            .build()
            .await
            .unwrap()
            .run()
            .await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Tenant A (Inference)
    let client_a = KelanClient::builder()
        .config("tenant_a.toml")
        .build()
        .await?;
    let _session_a = client_a
        .connect("127.0.0.1:9999")
        .intent(IntentCode::ModelInference)
        .await?;
    println!("[Tenant A] Inference session established.");

    // Tenant B (Telemetry)
    let client_b = KelanClient::builder()
        .config("tenant_b.toml")
        .build()
        .await?;
    let _session_b = client_b
        .connect("127.0.0.1:9999")
        .intent(IntentCode::Telemetry)
        .await?;
    println!("[Tenant B] Telemetry session established.");

    Ok(())
}
