//! HTTP control plane server using Axum.
//!
//! Provides REST endpoints for identity registration, resolution,
//! session revocation, and health checks.

use crate::registry::{IdentityRegistry, RegisteredIdentity};
use crate::revocation::RevocationList;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// Shared application state for the control plane.
#[derive(Clone)]
pub struct AppState {
    pub registry: IdentityRegistry,
    pub revocations: RevocationList,
    pub started_at: Instant,
}

/// Request body for identity registration.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub entity_id: String,
    pub public_key: String,
    pub name: String,
    pub entity_type: String,
    pub addresses: Vec<String>,
}

/// Response for registration.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
}

/// Request body for identity resolution.
#[derive(Debug, Deserialize)]
pub struct ResolveRequest {
    pub entity_id: String,
}

/// Response for resolution.
#[derive(Debug, Serialize)]
pub struct ResolveResponse {
    pub found: bool,
    pub name: Option<String>,
    pub entity_type: Option<String>,
    pub addresses: Vec<String>,
}

/// Request body for session revocation.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RevokeRequest {
    pub session_id: u64,
    pub reason: String,
}

/// Response for revocation.
#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub success: bool,
    pub message: String,
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_secs: u64,
    pub registered_identities: usize,
    pub revoked_sessions: usize,
}

/// Build the Axum router with all control plane endpoints.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/register", post(register_handler))
        .route("/resolve", post(resolve_handler))
        .route("/revoke", post(revoke_handler))
        .with_state(Arc::new(state))
}

/// Start the control plane HTTP server.
///
/// # Errors
///
/// Returns an error if the server cannot bind or encounters a fatal error.
pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState {
        registry: IdentityRegistry::new(),
        revocations: RevocationList::new(),
        started_at: Instant::now(),
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("Control plane listening on 0.0.0.0:8080");

    axum::serve(listener, app).await?;

    Ok(())
}

// ────────────────────────── Handlers ──────────────────────────

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".into(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        registered_identities: state.registry.len(),
        revoked_sessions: state.revocations.len(),
    })
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<RegisterResponse>) {
    let entity_id = match hex_to_bytes32(&req.entity_id) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RegisterResponse {
                    success: false,
                    message: "invalid entity_id hex".into(),
                }),
            );
        }
    };

    let public_key = match hex_to_bytes32(&req.public_key) {
        Some(pk) => pk,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RegisterResponse {
                    success: false,
                    message: "invalid public_key hex".into(),
                }),
            );
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    state.registry.register(RegisteredIdentity {
        entity_id,
        public_key,
        name: req.name,
        entity_type: req.entity_type,
        addresses: req.addresses,
        registered_at: now,
    });

    (
        StatusCode::OK,
        Json(RegisterResponse {
            success: true,
            message: "identity registered".into(),
        }),
    )
}

async fn resolve_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResolveRequest>,
) -> (StatusCode, Json<ResolveResponse>) {
    let entity_id = match hex_to_bytes32(&req.entity_id) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ResolveResponse {
                    found: false,
                    name: None,
                    entity_type: None,
                    addresses: vec![],
                }),
            );
        }
    };

    match state.registry.resolve(&entity_id) {
        Ok(identity) => (
            StatusCode::OK,
            Json(ResolveResponse {
                found: true,
                name: Some(identity.name),
                entity_type: Some(identity.entity_type),
                addresses: identity.addresses,
            }),
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(ResolveResponse {
                found: false,
                name: None,
                entity_type: None,
                addresses: vec![],
            }),
        ),
    }
}

async fn revoke_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevokeRequest>,
) -> (StatusCode, Json<RevokeResponse>) {
    let newly_revoked = state.revocations.revoke(req.session_id);

    (
        StatusCode::OK,
        Json(RevokeResponse {
            success: true,
            message: if newly_revoked {
                format!("session {:#018x} revoked", req.session_id)
            } else {
                format!("session {:#018x} already revoked", req.session_id)
            },
        }),
    )
}

/// Parse a hex string into a [u8; 32] array.
fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return None;
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}
