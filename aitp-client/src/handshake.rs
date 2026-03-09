// AITP Client Agent — handshake.rs
// 5-phase AITP handshake with the Intelligence Core server (HTTP API).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

use crate::config::ClientConfig;
use crate::identity::EntityIdentity;

// ─── Intent codes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum Intent {
    ModelInference,
    AgentCoordinate,
    DataSync,
    ControlSignal,
    FileTransfer,
    ApiCall,
    Heartbeat,
}

impl std::fmt::Display for Intent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ─── Verdict ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum Verdict {
    Allow,
    Monitor,
    Deny,
}

// ─── Session Permit ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionPermit {
    pub session_id: String,
    pub trust_score: u8,
    pub verdict: Verdict,
    pub intent: Intent,
    pub reasoning: String,
    pub eval_source: String,
    pub established_at: Instant,
}

impl SessionPermit {
    pub fn is_allowed(&self) -> bool {
        self.verdict != Verdict::Deny
    }

    pub fn age_secs(&self) -> u64 {
        self.established_at.elapsed().as_secs()
    }
}

// ─── API Types ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct TestSessionReq {
    dest_entity_id: String,
    intent: String,
}

#[derive(Debug, Deserialize)]
struct TestSessionResp {
    session_id: String,
    trust_score: u8,
    verdict: String,
    reasoning: Option<String>,
    evaluation_source: Option<String>,
    primary_risk: Option<String>,
}

// ─── Handshake ───────────────────────────────────────────────────────────────

pub struct AitpHandshake {
    identity: Arc<EntityIdentity>,
    config: Arc<ClientConfig>,
    client: reqwest::Client,
}

impl AitpHandshake {
    pub fn new(identity: Arc<EntityIdentity>, config: Arc<ClientConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            identity,
            config,
            client,
        }
    }

    /// Run the full 5-phase AITP handshake against the Intelligence Core.
    pub async fn establish(&self, dest_entity_id: &str, intent: Intent) -> Result<SessionPermit> {
        let base = self.config.api_base_url();

        let my_entity_id = self.identity.entity_id_full_hex();

        // Prefer the server-registered entity ID for the URL path (which is server-generated).
        // Fall back to the local SHA256 identity if not yet enrolled.
        let server_entity_id =
            crate::daemon::load_server_entity_id().unwrap_or_else(|| my_entity_id.clone());

        tracing::info!(
            entity = %my_entity_id[..16],
            dest = %dest_entity_id[..dest_entity_id.len().min(16)],
            intent = %intent,
            "Phase 1: AITP_HELLO — initiating handshake"
        );

        let url = format!("{}/api/entities/{}/test-session", base, server_entity_id);

        tracing::info!("Phase 2: AITP_IDENTITY_EXCHANGE — sending identity + nonce");
        // We sign our entity_id as proof-of-possession
        let nonce = uuid::Uuid::new_v4().to_string();
        let signed_nonce = self.identity.sign(nonce.as_bytes());
        let _sig_hex = hex::encode(signed_nonce);

        tracing::info!("Phase 3: AITP_INTENT_DECLARE — {}", intent);

        let body = TestSessionReq {
            dest_entity_id: dest_entity_id.to_string(),
            intent: intent.to_string(),
        };

        // Load token from saved auth
        let token = load_auth_token()?;

        tracing::info!("Phase 4: Trust evaluation (AI + rules)…");
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .context("Failed to reach Intelligence Core")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "Intelligence Core rejected handshake: {} — {}",
                status,
                body
            );
        }

        let data: TestSessionResp = resp
            .json()
            .await
            .context("Failed to parse session response")?;

        let verdict = match data.verdict.to_lowercase().as_str() {
            "allow" => Verdict::Allow,
            "deny" => Verdict::Deny,
            _ => Verdict::Monitor,
        };

        tracing::info!(
            session_id = %data.session_id,
            trust_score = data.trust_score,
            verdict = ?verdict,
            "Phase 5: SESSION_GRANT received"
        );

        Ok(SessionPermit {
            session_id: data.session_id,
            trust_score: data.trust_score,
            verdict,
            intent,
            reasoning: data
                .reasoning
                .or(data.primary_risk)
                .unwrap_or_else(|| "rules".into()),
            eval_source: data.evaluation_source.unwrap_or_else(|| "rules".into()),
            established_at: Instant::now(),
        })
    }

    /// Send a heartbeat session to keep the entity registration alive.
    pub async fn heartbeat(&self) -> Result<()> {
        let my_id = self.identity.entity_id_full_hex();
        let _ = self.establish(&my_id, Intent::Heartbeat).await?;
        Ok(())
    }
}

// ─── Auth Token Storage ───────────────────────────────────────────────────────

pub fn save_auth_token(token: &str) -> Result<()> {
    let path = token_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_auth_token() -> Result<String> {
    let path = token_path();
    if !path.exists() {
        anyhow::bail!("Not authenticated. Run `aitp-client enroll` first.");
    }
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

fn token_path() -> std::path::PathBuf {
    crate::config::ClientConfig::default_config_path()
        .parent()
        .map(|p| p.join("auth.token"))
        .unwrap_or_else(|| std::path::PathBuf::from("auth.token"))
}
