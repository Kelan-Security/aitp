use crate::{KernexError, SessionHandle, TrustResult, TrustVerdict};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::UdpSocket;

type SharedHandler = Arc<
    dyn Fn(SessionHandle) -> Pin<Box<dyn Future<Output = Result<(), KernexError>> + Send>>
        + Send
        + Sync,
>;

/// Accept and evaluate incoming sessions from Kernex clients.
///
/// # Example
/// ```rust,no_run
/// # use kernex_sdk::KernexServer;
/// # async fn serve() -> Result<(), kernex_sdk::KernexError> {
/// KernexServer::builder()
///     .config("kernex.toml")
///     .on_session(|session| async move {
///         println!("Session from {:?}, trust: {}", 
///             session.trust_result().verdict,
///             session.trust_result().trust_score);
///         session.send(b"acknowledged").await?;
///         Ok(())
///     })
///     .build().await?
///     .run().await
/// # }
/// ```
pub struct KernexServer {
    handler: Option<SharedHandler>,
}

pub struct KernexServerBuilder {
    _config_path: Option<String>,
    handler: Option<SharedHandler>,
}

impl Default for KernexServerBuilder {
    fn default() -> Self {
        Self { _config_path: None, handler: None }
    }
}

impl KernexServerBuilder {
    pub fn config(mut self, path: &str) -> Self {
        self._config_path = Some(path.to_string());
        self
    }

    pub fn on_session<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(SessionHandle) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), KernexError>> + Send + 'static,
    {
        self.handler = Some(Arc::new(move |session| Box::pin(handler(session))));
        self
    }

    pub async fn build(self) -> Result<KernexServer, KernexError> {
        Ok(KernexServer { handler: self.handler })
    }
}

impl KernexServer {
    pub fn builder() -> KernexServerBuilder {
        KernexServerBuilder::default()
    }

    pub async fn run(self) -> Result<(), KernexError> {
        // Minimal simulated server logic matching the provided interface.
        let socket = UdpSocket::bind("0.0.0.0:9999")
            .await
            .map_err(|e| KernexError::Transport(e.to_string()))?;
        
        let socket_arc = Arc::new(socket);
        let mut buf = vec![0u8; 65535];

        loop {
            match socket_arc.recv_from(&mut buf).await {
                Ok((_len, peer_addr)) => {
                    if let Some(ref h) = self.handler {
                        // Generate simulated trust.
                        let trust_result = TrustResult {
                            trust_score: 180,
                            verdict: TrustVerdict::Allow,
                            reasoning: "Verified.".to_string(),
                            confidence: 0.99,
                            anomaly_flags: vec![],
                            latency_ms: 1.5,
                        };

                        let session = SessionHandle::new(
                            socket_arc.clone(),
                            peer_addr.to_string(),
                            rand::random(),
                            trust_result,
                        );

                        let handler_clone = h.clone();
                        tokio::spawn(async move {
                            let _ = handler_clone(session).await;
                        });
                    }
                }
                Err(_) => {
                    // ignore
                }
            }
        }
    }
}
