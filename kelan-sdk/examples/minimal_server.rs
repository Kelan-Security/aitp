use kelan_sdk::KelanServer;

#[tokio::main]
async fn main() -> Result<(), kelan_sdk::KelanError> {
    println!("Starting Minimal Kelan Security Server on UDP 9999...");
    KelanServer::builder()
        .config("kelan.toml")
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
