use thiserror::Error;

/// SDK Errors
#[derive(Debug, Error)]
pub enum KernexError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("Connection refused: {0}")]
    ConnectionRefused(String),
    #[error("Access Denied: Trust score too low ({0})")]
    AccessDenied(u8),
    #[error("Timeout after {0}ms")]
    Timeout(u64),
    #[error("Crypto error: {0}")]
    Crypto(String),
}
