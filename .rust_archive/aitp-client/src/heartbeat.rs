// Kelan Security Client Agent — heartbeat.rs
// 30-second heartbeat to Intelligence Core.

use std::sync::Arc;
use std::time::Duration;

use crate::config::AgentConfig;
use crate::identity::EntityIdentity;

pub async fn run_heartbeat(config: Arc<AgentConfig>, identity: Arc<EntityIdentity>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        interval.tick().await;

        let token = match &config.agent.api_token {
            Some(t) => t.clone(),
            None => continue,
        };

        let entity_id = identity.entity_id_hex();
        let url = format!("{}/api/entities/{}/heartbeat", config.ic_url(), entity_id);

        match client
            .post(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({"status": "active"}))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("Heartbeat OK");
            }
            Ok(resp) => {
                tracing::warn!("Heartbeat returned {}", resp.status());
            }
            Err(e) => {
                tracing::warn!("Heartbeat failed: {}", e);
            }
        }
    }
}
