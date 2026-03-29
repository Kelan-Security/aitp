use crate::{KelanError, TrustResult};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// An established, evaluated session.
/// Dropped sessions are automatically closed.
pub struct SessionHandle {
    // private fields
    socket: Arc<UdpSocket>,
    target_addr: String,
    session_id: u64,
    trust_result: TrustResult,
}

impl SessionHandle {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        target_addr: String,
        session_id: u64,
        trust_result: TrustResult,
    ) -> Self {
        Self {
            socket,
            target_addr,
            session_id,
            trust_result,
        }
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), KelanError> {
        self.socket
            .send_to(data, &self.target_addr)
            .await
            .map_err(|e| KelanError::Transport(e.to_string()))?;
        Ok(())
    }

    pub async fn recv(&self) -> Result<Vec<u8>, KelanError> {
        let mut buf = vec![0u8; 65535];
        let (len, _) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| KelanError::Transport(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    pub async fn close(self) -> Result<(), KelanError> {
        // Drop automatically closes the simulated session.
        Ok(())
    }

    pub fn trust_result(&self) -> &TrustResult {
        &self.trust_result
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}
