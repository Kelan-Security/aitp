pub mod client;
pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod session;

// Re-export everything the user needs
pub use client::{KernexClient, KernexClientBuilder};
pub use server::{KernexServer, KernexServerBuilder};
pub use session::SessionHandle;
pub use protocol::{IntentCode, TrustResult, TrustVerdict};
pub use config::KernexConfig;
pub use error::KernexError;

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
