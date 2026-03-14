use kernex_sdk::{KernexClient, IntentCode};

#[tokio::main]
async fn main() -> Result<(), kernex_sdk::KernexError> {
    let client = KernexClient::builder().config("kernex.toml").build().await?;
    let session = client.connect("127.0.0.1:9999")
        .intent(IntentCode::ModelInference)
        .await?;
    println!("Session established. Sending payload...");
    session.send(b"hello").await?;
    Ok(())
}
