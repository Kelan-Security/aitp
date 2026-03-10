// AITP Client Agent — daemon.rs
// Main daemon loop: server connection, heartbeat, reconnect logic.

use anyhow::Result;
use std::sync::Arc;
use tokio::time::{interval, Duration};

use crate::config::ClientConfig;
use crate::handshake::{AitpHandshake, Intent};
use crate::identity::EntityIdentity;
use crate::interceptor::Interceptor;
use crate::ipc::{start_ipc_server, DaemonState};
use crate::session::SessionTable;

const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const SESSION_PURGE_INTERVAL_SECS: u64 = 300;

pub async fn run_daemon(config: ClientConfig, identity: EntityIdentity) -> Result<()> {
    let config = Arc::new(config);
    let identity = Arc::new(identity);
    let sessions = SessionTable::new();

    tracing::info!(
        entity = %identity.entity_id_hex(),
        server = %config.api_base_url(),
        mode = %config.interception.mode,
        "AITP Client daemon starting"
    );

    // Build shared daemon state for IPC server
    let daemon_state = Arc::new(DaemonState {
        entity_id_short: identity.entity_id_hex(),
        public_key_hex: identity.public_key_hex(),
        connected: tokio::sync::Mutex::new(false),
        server_address: config.api_base_url(),
        sessions: sessions.clone(),
        started_at: std::time::Instant::now(),
        interception_mode: config.interception.mode.clone(),
    });

    // 1. Start IPC server for `aitp-client status`
    {
        let state = Arc::clone(&daemon_state);
        tokio::spawn(async move {
            if let Err(e) = start_ipc_server(state).await {
                tracing::error!("IPC server error: {}", e);
            }
        });
    }

    // 2. Start connection interceptor
    {
        let interceptor = Interceptor::new(config.interception.clone());
        tokio::spawn(async move {
            if let Err(e) = interceptor.start().await {
                tracing::error!("Interceptor error: {}", e);
            }
        });
    }

    // 3. Build the handshake client
    let handshake = AitpHandshake::new(Arc::clone(&identity), Arc::clone(&config));

    // 4. Initial connectivity check — attempt enroll/heartbeat with exponential backoff
    let mut backoff_secs = 2u64;
    loop {
        match handshake.heartbeat().await {
            Ok(_) => {
                *daemon_state.connected.lock().await = true;
                tracing::info!("Connected to Intelligence Core");
                break;
            }
            Err(e) => {
                tracing::warn!("Failed to connect (retrying in {}s): {}", backoff_secs, e);
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }

    // 5. Heartbeat loop
    let heartbeat_state = Arc::clone(&daemon_state);
    let heartbeat_config = Arc::clone(&config);
    let heartbeat_identity = Arc::clone(&identity);
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        loop {
            tick.tick().await;
            let hs = AitpHandshake::new(
                Arc::clone(&heartbeat_identity),
                Arc::clone(&heartbeat_config),
            );
            match hs.heartbeat().await {
                Ok(_) => {
                    *heartbeat_state.connected.lock().await = true;
                    tracing::debug!("Heartbeat OK");
                }
                Err(e) => {
                    *heartbeat_state.connected.lock().await = false;
                    tracing::warn!("Heartbeat failed: {}. Reconnecting…", e);

                    // Exponential backoff reconnect
                    let mut backoff = 2u64;
                    loop {
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        let hs2 = AitpHandshake::new(
                            Arc::clone(&heartbeat_identity),
                            Arc::clone(&heartbeat_config),
                        );
                        if hs2.heartbeat().await.is_ok() {
                            *heartbeat_state.connected.lock().await = true;
                            tracing::info!("Reconnected to Intelligence Core");
                            break;
                        }
                        backoff = (backoff * 2).min(60);
                    }
                }
            }
        }
    });

    // 6. Session purge loop
    {
        let s = sessions.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(SESSION_PURGE_INTERVAL_SECS));
            loop {
                tick.tick().await;
                s.purge_expired();
                tracing::debug!("Session table purged — {} active", s.active_count());
            }
        });
    }

    tracing::info!("AITP Client daemon running — Ctrl+C to stop");

    // 7. Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutdown signal received — stopping AITP Client");

    // Clean up IPC socket
    let _ = std::fs::remove_file(crate::ipc::IPC_SOCKET_PATH);

    Ok(())
}

/// Helper: enroll this device with the Intelligence Core.
pub async fn enroll_device(config: &ClientConfig, identity: &EntityIdentity) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    // Determine entity name
    let entity_name = if config.agent.entity_name.is_empty() {
        gethostname()
    } else {
        config.agent.entity_name.clone()
    };

    // Step 1: Authenticate (create or sign in to an organisation)
    let base = config.api_base_url();
    let creds = serde_json::json!({
        "email": std::env::var("AITP_EMAIL").unwrap_or_else(|_| "admin@acme.com".into()),
        "password": std::env::var("AITP_PASSWORD").unwrap_or_else(|_| "supersecret123".into()),
    });

    let auth_resp: serde_json::Value = client
        .post(format!("{}/api/auth/signin", base))
        .json(&creds)
        .send()
        .await?
        .json()
        .await?;

    let token = auth_resp["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Auth failed: {:?}", auth_resp))?;

    crate::handshake::save_auth_token(token)?;
    tracing::info!("Authenticated with Intelligence Core");

    // Step 2: Register the entity
    let entity_body = serde_json::json!({
        "name": entity_name,
        "entity_type": config.agent.entity_type,
        "department": config.agent.department,
        "clearance_level": config.agent.clearance_level,
        "public_key_hex": identity.public_key_hex(),
        "entity_id_hex": identity.entity_id_full_hex(),
    });

    let reg_resp = client
        .post(format!("{}/api/entities", base))
        .bearer_auth(token)
        .json(&entity_body)
        .send()
        .await?;

    if reg_resp.status().is_success() {
        let data: serde_json::Value = reg_resp.json().await?;
        let server_entity_id = data["entity_id"].as_str().unwrap_or("").to_string();
        tracing::info!(entity_id = %server_entity_id, "Entity registered");
        // Persist the server-assigned entity ID for future use
        save_server_entity_id(&server_entity_id)?;
        println!(
            "✓ Enrolled: {} (server_id: {}...)",
            entity_name,
            &server_entity_id[..server_entity_id.len().min(12)]
        );
    } else {
        let status = reg_resp.status();
        let body: serde_json::Value = reg_resp.json().await.unwrap_or_default();
        if body["error"]
            .as_str()
            .is_some_and(|e| e.contains("already"))
        {
            println!(
                "✓ Already enrolled: {} ({})",
                entity_name,
                identity.entity_id_hex()
            );
        } else {
            anyhow::bail!("Registration failed: {} — {:?}", status, body);
        }
    }

    Ok(())
}

fn entity_id_path() -> std::path::PathBuf {
    crate::config::ClientConfig::default_config_path()
        .parent()
        .map(|p| p.join("server_entity_id"))
        .unwrap_or_else(|| std::path::PathBuf::from("server_entity_id"))
}

pub fn save_server_entity_id(id: &str) -> Result<()> {
    let path = entity_id_path();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(&path, id)?;
    Ok(())
}

pub fn load_server_entity_id() -> Option<String> {
    std::fs::read_to_string(entity_id_path())
        .ok()
        .map(|s| s.trim().to_string())
}

/// Perform a single test handshake and print results.
#[allow(dead_code)]
pub async fn test_connection(config: &ClientConfig, _identity: &EntityIdentity) -> Result<()> {
    let identity = Arc::new(EntityIdentity::generate_or_load(config)?);
    drop(identity); // re-borrow
    let identity_arc = Arc::new(EntityIdentity::generate_or_load(config)?);
    let config_arc = Arc::new(config.clone());

    let handshake = AitpHandshake::new(identity_arc.clone(), config_arc);

    // Use self as destination for test (heartbeat)
    let dest_id = identity_arc.entity_id_full_hex();
    let intent = Intent::ModelInference;

    println!("Running 5-phase AITP handshake test…");
    println!("  Entity ID : {}", identity_arc.entity_id_hex());
    println!("  Server    : {}", config.api_base_url());
    println!("  Intent    : {}", intent);
    println!();

    let t0 = std::time::Instant::now();
    let permit = handshake.establish(&dest_id, intent).await?;
    let latency = t0.elapsed();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "  Session ID  : {}",
        &permit.session_id[..permit.session_id.len().min(16)]
    );
    println!("  Trust Score : {}", permit.trust_score);
    println!("  Verdict     : {:?}", permit.verdict);
    println!("  Source      : {}", permit.eval_source);
    println!("  Reasoning   : {}", permit.reasoning);
    println!("  Latency     : {}ms", latency.as_millis());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if permit.is_allowed() {
        println!("  ✓ Connection ALLOWED");
    } else {
        println!("  ✗ Connection DENIED");
    }

    Ok(())
}

fn gethostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            let output = std::process::Command::new("hostname").output();
            match output {
                Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
                Err(_) => "aitp-client".into(),
            }
        })
}
