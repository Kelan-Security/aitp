use kelan_sdk::{IntentCode, AitpClient, KelanConfig, SdkError};
use kelan_crypto::HybridSigningKey;

#[tokio::main]
async fn main() -> Result<(), SdkError> {
    let identity = HybridSigningKey::generate();
    let session = AitpClient::builder()
        .server("127.0.0.1:9999")
        .intent(IntentCode::ModelInference)
        .identity(identity)
        .connect()
        .await?;
    println!("Session established. ID: {}", session.session_id);
    Ok(())
}
