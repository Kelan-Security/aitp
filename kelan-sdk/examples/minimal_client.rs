use kelan_sdk::{KelanClient, IntentCode};

#[tokio::main]
async fn main() -> Result<(), kelan_sdk::KelanError> {
    let client = KelanClient::builder().config("kelan.toml").build().await?;
    let session = client.connect("127.0.0.1:9999")
        .intent(IntentCode::ModelInference)
        .await?;
    println!("Session established. Sending payload...");
    session.send(b"hello").await?;
    Ok(())
}
