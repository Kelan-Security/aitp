pub mod client;
pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod session;

// Re-export everything the user needs
pub use client::{KelanClient, KelanClientBuilder};
pub use server::{KelanServer, KelanServerBuilder};
pub use session::SessionHandle;
pub use protocol::{IntentCode, TrustResult, TrustVerdict};
pub use config::KelanConfig;
pub use error::KelanError;

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
