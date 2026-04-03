use crate::{KelanError, SessionHandle, TrustResult, TrustVerdict};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::UdpSocket;

type SharedHandler = Arc<
    dyn Fn(SessionHandle) -> Pin<Box<dyn Future<Output = Result<(), KelanError>> + Send>>
        + Send
        + Sync,
>;

/// Accept and evaluate incoming sessions from Kelan Security clients.
///
/// # Example
/// ```rust,no_run
/// # use kelan_sdk::KelanServer;
/// # async fn serve() -> Result<(), kelan_sdk::KelanError> {
/// KelanServer::builder()
///     .config("kelan.toml")
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
pub struct KelanServer {
    handler: Option<SharedHandler>,
}

#[derive(Default)]
pub struct KelanServerBuilder {
    _config_path: Option<String>,
    handler: Option<SharedHandler>,
}

impl KelanServerBuilder {
    pub fn config(mut self, path: &str) -> Self {
        self._config_path = Some(path.to_string());
        self
    }

    pub fn on_session<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(SessionHandle) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), KelanError>> + Send + 'static,
    {
        self.handler = Some(Arc::new(move |session| Box::pin(handler(session))));
        self
    }

    pub async fn build(self) -> Result<KelanServer, KelanError> {
        Ok(KelanServer {
            handler: self.handler,
        })
    }
}

impl KelanServer {
    pub fn builder() -> KelanServerBuilder {
        KelanServerBuilder::default()
    }

    pub async fn run(self) -> Result<(), KelanError> {
        // Minimal simulated server logic matching the provided interface.
        let socket = UdpSocket::bind("0.0.0.0:9999")
            .await
            .map_err(|e| KelanError::Transport(e.to_string()))?;

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
