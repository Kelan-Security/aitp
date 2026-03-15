// Kernex Client Agent — enroll.rs
// Device enrollment with the Kernex Intelligence Core.

use std::path::Path;
use crate::config::AgentConfig;
use crate::identity::EntityIdentity;

/// Enroll this device with the Intelligence Core.
/// Registers the entity via REST API and saves the token to config.
pub async fn run(
    server_address: String,
    org_token: String,
    config_path: &Path,
) -> anyhow::Result<()> {
    println!("Enrolling device with Kernex Intelligence Core...");
    println!("Server: {}", server_address);

    // 1. Generate or load keypair
    let identity = EntityIdentity::load_or_generate(config_path.parent())?;
    println!("Entity ID: {}", identity.entity_id_hex());
    println!("Public Key: {}...", &identity.public_key_hex()[..32.min(identity.public_key_hex().len())]);

    // 2. Auto-detect device name
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|| "unknown-device".to_string())
        });

    // 3. POST /api/entities to register
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let ic_url = if server_address.starts_with("http") {
        server_address.clone()
    } else {
        format!("http://{}:3000", server_address)
    };

    let response = client
        .post(format!("{}/api/entities", ic_url))
        .bearer_auth(&org_token)
        .json(&serde_json::json!({
            "name": hostname,
            "entity_type": "workstation",
            "public_key": identity.public_key_hex(),
            "entity_id": identity.entity_id_hex(),
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let err_text = response.text().await?;
        // Check for "already enrolled" case
        if err_text.contains("already") {
            println!("Device already enrolled. Updating config...");
        } else {
            anyhow::bail!("Enrolment failed ({}): {}", status, err_text);
        }
    } else {
        let entity: serde_json::Value = response.json().await?;
        println!("Enrolment successful!");
        println!(
            "Entity registered as: {}",
            entity["name"].as_str().unwrap_or("unknown")
        );
    }

    // 4. Save token + server address to config
    let mut config = AgentConfig::load(config_path).unwrap_or_default();
    config.server.address = server_address
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();
    config.agent.api_token = Some(org_token);

    let config_toml = toml::to_string_pretty(&config)?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, &config_toml)?;

    println!("Config saved to: {}", config_path.display());
    println!();
    println!("Start the agent with:");
    println!("  sudo kernex-agent start");
    println!("  sudo systemctl start kernex-agent  (if installed as service)");

    Ok(())
}
