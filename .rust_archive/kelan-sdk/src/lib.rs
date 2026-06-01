pub mod builder;
pub mod client;
pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod session;

// Re-export everything the user needs
pub use client::AitpClient;
pub use builder::AitpClientBuilder;
pub use config::KelanConfig;
pub use error::SdkError;
pub use aitp_core::header::IntentCode;
pub use protocol::{TrustResult, TrustVerdict};
pub use server::{KelanServer, KelanServerBuilder};
pub use session::EstablishedSession;

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
