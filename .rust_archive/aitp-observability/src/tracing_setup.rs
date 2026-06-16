//! Structured JSON tracing setup for AITP.
//!
//! Configures the `tracing` subscriber to emit structured JSON logs
//! with timestamp, level, target, and span fields. Reads `AITP_LOG_LEVEL`
//! from the environment (default: `info`).

use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the global tracing subscriber with JSON output.
///
/// Must be called once at program startup. Reads the `AITP_LOG_LEVEL`
/// environment variable to set the log filter (default: `info`).
///
/// # Panics
///
/// Panics if a global subscriber has already been set.
pub fn init_tracing() {
    let filter =
        EnvFilter::try_from_env("AITP_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}
