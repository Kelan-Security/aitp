#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Unexpected handshake phase: {0:?}")]
    UnexpectedPhase(String),
    
    #[error("Server returned invalid signature")]
    InvalidServerSignature,
    
    #[error("Missing session ID in server response")]
    MissingSessionId,
    
    #[error("Handshake failed — server rejected")]
    HandshakeFailed,
    
    #[error("Timeout waiting for server response")]
    Timeout,
    
    #[error("Server denied session: {0}")]
    Denied(String),
}
