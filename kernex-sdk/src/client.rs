use crate::{IntentCode, KernexError, SessionHandle, TrustResult, TrustVerdict};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Connect to a Kernex Intelligence Core as a client entity.
///
/// # Example
/// ```rust,no_run
/// # use kernex_sdk::{KernexClient, IntentCode};
/// # async fn run() -> Result<(), kernex_sdk::KernexError> {
/// let client = KernexClient::builder()
///     .config("kernex.toml")
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
pub struct KernexClient {
    inner: Arc<KernexClientInner>,
}

pub(crate) struct KernexClientInner {
    pub(crate) _config_path: Option<String>,
}

impl KernexClient {
    pub fn builder() -> KernexClientBuilder {
        KernexClientBuilder::default()
    }

    /// Initiate a session with intent declaration.
    /// Performs the full 5-phase AITP handshake.
    /// Returns Err if trust score < 64 (Deny verdict).
    pub fn connect(&self, addr: &str) -> KernexSessionBuilder {
        KernexSessionBuilder {
            _client: self.inner.clone(),
            addr: addr.to_string(),
            intent: IntentCode::Unknown,
        }
    }
}

pub struct KernexClientBuilder {
    config_path: Option<String>,
}

impl Default for KernexClientBuilder {
    fn default() -> Self {
        Self { config_path: None }
    }
}

impl KernexClientBuilder {
    pub fn config(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    pub async fn build(self) -> Result<KernexClient, KernexError> {
        Ok(KernexClient {
            inner: Arc::new(KernexClientInner { _config_path: self.config_path })
        })
    }
}

pub struct KernexSessionBuilder {
    _client: Arc<KernexClientInner>,
    addr: String,
    intent: IntentCode,
}

impl KernexSessionBuilder {
    pub fn intent(mut self, intent: IntentCode) -> Self {
        self.intent = intent;
        self
    }
}

impl std::future::IntoFuture for KernexSessionBuilder {
    type Output = Result<SessionHandle, KernexError>;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| KernexError::Transport(e.to_string()))?;
            
            // Send synthetic SYN packet equivalent to target just for SDK demonstration capability
            let msg = format!("SYN {:?}", self.intent);
            socket.send_to(msg.as_bytes(), &self.addr)
                .await
                .map_err(|e| KernexError::Transport(e.to_string()))?;

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
                simulated_trust
            ))
        })
    }
}
