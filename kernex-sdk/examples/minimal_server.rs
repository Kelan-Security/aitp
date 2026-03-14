use kernex_sdk::KernexServer;

#[tokio::main]
async fn main() -> Result<(), kernex_sdk::KernexError> {
    println!("Starting Minimal Kernex Server on UDP 9999...");
    KernexServer::builder()
        .config("kernex.toml")
        .on_session(|session| async move {
            println!("Session from {}, trust: {}", 
                session.session_id(),
                session.trust_result().trust_score);
            session.send(b"acknowledged").await?;
            Ok(())
        })
        .build().await?
        .run().await
}
