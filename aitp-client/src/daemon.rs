// Kelan Security Client Agent — daemon.rs
// Main daemon loop orchestrating all subsystems.

use std::sync::Arc;
use tokio::time::Duration;

use crate::channel::IcChannel;
use crate::config::AgentConfig;
use crate::identity::EntityIdentity;
use crate::ipc;
use crate::session::SessionTable;

pub async fn run(config: Arc<AgentConfig>, config_path: std::path::PathBuf) -> anyhow::Result<()> {
    // 1. Load identity (use same dir as config for keys)
    let identity = Arc::new(EntityIdentity::load_or_generate()?);
    let sessions = SessionTable::new();

    tracing::info!(
        entity_id = %identity.short_id(),
        server = %config.ic_url(),
        mode = %config.interception.mode,
        "Kelan Security Client Agent starting"
    );

    // 2. Start IPC server for `kelan-agent status`
    {
        let sessions_clone = sessions.clone();
        let config_clone = Arc::clone(&config);
        let identity_clone = Arc::clone(&identity);
        tokio::spawn(async move {
            if let Err(e) =
                ipc::start_ipc_server(sessions_clone, config_clone, identity_clone).await
            {
                tracing::error!("IPC server error: {}", e);
            }
        });
    }

    // 3. Start heartbeat
    {
        let config_clone = Arc::clone(&config);
        let identity_clone = Arc::clone(&identity);
        tokio::spawn(async move {
            crate::heartbeat::run_heartbeat(config_clone, identity_clone).await;
        });
    }

    // 4. Start command channel (WebSocket)
    {
        let channel = IcChannel::new(Arc::clone(&config), sessions.clone());
        tokio::spawn(async move {
            channel.run().await;
        });
    }

    // 5. Start session purge loop
    {
        let sessions_clone = sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                sessions_clone.purge_expired().await;
                let active = sessions_clone.active_count().await;
                tracing::debug!(active, "Session table purged");
            }
        });
    }

    // 6. Start interceptor (SOCKS5 proxy / iptables / monitor)
    // This is the main blocking loop
    let config_clone = Arc::clone(&config);
    let identity_clone = Arc::clone(&identity);
    let sessions_clone = sessions.clone();

    tokio::select! {
        result = crate::interceptor::start(config_clone, identity_clone, sessions_clone) => {
            if let Err(e) = result {
                tracing::error!("Interceptor error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received");
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(ipc::IPC_SOCKET_PATH);
    tracing::info!("Kelan Security Client Agent stopped");

    Ok(())
}
