//! AITP Control Plane — Server entry point
//!
//! Launches the HTTP control plane server for identity registration,
//! resolution, and session revocation management.

mod registry;
mod revocation;
mod server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    aitp_observability::tracing_setup::init_tracing();

    tracing::info!("Starting AITP Control Plane server");

    // Start the control plane server
    server::run_server().await?;

    Ok(())
}
