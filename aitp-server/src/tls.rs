use std::path::PathBuf;
use axum_server::tls_rustls::RustlsConfig;

use crate::config::AppConfig;

/// Describes how the HTTP server should bind.
pub enum ServerMode {
    /// Plain HTTP for local development.
    Http { port: u16 },
    /// HTTPS with an HTTP→HTTPS redirect on `http_port`.
    Https {
        http_port:  u16,
        https_port: u16,
        cert:       PathBuf,
        key:        PathBuf,
    },
}

/// Inspect `AppConfig` and decide whether to run HTTP or HTTPS.
pub fn detect_mode(config: &AppConfig) -> ServerMode {
    match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert), Some(key)) => {
            tracing::warn!("╔══════════════════════════════════════════╗");
            tracing::warn!("║   HTTPS PRODUCTION MODE ACTIVE           ║");
            tracing::warn!("╚══════════════════════════════════════════╝");
            ServerMode::Https {
                http_port:  config.redirect_port,
                https_port: config.https_port,
                cert:       cert.into(),
                key:        key.into(),
            }
        }
        _ => {
            tracing::warn!("⚠  Running in HTTP DEVELOPMENT MODE");
            tracing::warn!("⚠  Set TLS_CERT_PATH and TLS_KEY_PATH for production");
            ServerMode::Http {
                port: config.http_port,
            }
        }
    }
}

/// Load a `RustlsConfig` from PEM cert + key files on disk.
pub async fn load_rustls_config(
    cert_path: &PathBuf,
    key_path:  &PathBuf,
) -> anyhow::Result<RustlsConfig> {
    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| anyhow::anyhow!(
            "Failed to load TLS config (cert={}, key={}): {}",
            cert_path.display(),
            key_path.display(),
            e
        ))?;
    Ok(config)
}
