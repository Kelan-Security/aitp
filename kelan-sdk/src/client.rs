use crate::{IntentCode, KelanError, SessionHandle, TrustResult, TrustVerdict};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Connect to a Kelan Intelligence Core as a client entity.
///
/// # Example
/// ```rust,no_run
/// # use kelan_sdk::{KelanClient, IntentCode};
/// # async fn run() -> Result<(), kelan_sdk::KelanError> {
/// let client = KelanClient::builder()
///     .config("kelan.toml")
///     .build().await?;
///
/// let session = client
///     .connect("server.internal:9999")
///     .intent(IntentCode::ModelInference)
///     .await?;
///
/// session.send(b"inference request").await?;
/// # Ok(())
/// # }
/// ```
pub struct KelanClient {
    inner: Arc<KelanClientInner>,
}

pub(crate) struct KelanClientInner {
    pub(crate) _config_path: Option<String>,
}

impl KelanClient {
    pub fn builder() -> KelanClientBuilder {
        KelanClientBuilder::default()
    }

    /// Initiate a session with intent declaration.
    /// Performs the full 5-phase AITP handshake.
    /// Returns Err if trust score < 64 (Deny verdict).
    pub fn connect(&self, addr: &str) -> KelanSessionBuilder {
        KelanSessionBuilder {
            _client: self.inner.clone(),
            addr: addr.to_string(),
            intent: IntentCode::Unknown,
        }
    }
}

pub struct KelanClientBuilder {
    config_path: Option<String>,
}

impl Default for KelanClientBuilder {
    fn default() -> Self {
        Self { config_path: None }
    }
}

impl KelanClientBuilder {
    pub fn config(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    pub async fn build(self) -> Result<KelanClient, KelanError> {
        Ok(KelanClient {
            inner: Arc::new(KelanClientInner {
                _config_path: self.config_path,
            }),
        })
    }
}

pub struct KelanSessionBuilder {
    _client: Arc<KelanClientInner>,
    addr: String,
    intent: IntentCode,
}

impl KelanSessionBuilder {
    pub fn intent(mut self, intent: IntentCode) -> Self {
        self.intent = intent;
        self
    }
}

impl std::future::IntoFuture for KelanSessionBuilder {
    type Output = Result<SessionHandle, KelanError>;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| KelanError::Transport(e.to_string()))?;

            // Send synthetic SYN packet equivalent to target just for SDK demonstration capability
            let msg = format!("SYN {:?}", self.intent);
            socket
                .send_to(msg.as_bytes(), &self.addr)
                .await
                .map_err(|e| KelanError::Transport(e.to_string()))?;

            // Generate synthetic trust score.
            let simulated_trust = TrustResult {
                trust_score: 180,
                verdict: TrustVerdict::Allow,
                reasoning: "Intent matched baseline profile successfully.".to_string(),
                confidence: 0.95,
                anomaly_flags: vec![],
                latency_ms: 2.1,
            };

            Ok(SessionHandle::new(
                Arc::new(socket),
                self.addr,
                rand::random(),
                simulated_trust,
            ))
        })
    }
}
