use axum::{extract::FromRequestParts, http::request::Parts};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{error::AppError, state::AppState};

/// Claims embedded in every AITP JWT
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AitpClaims {
    pub sub: String,      // org_id
    pub org_id: String,   // org_id (explicit field for clarity)
    pub org_name: String, // human-readable org name
    pub email: String,
    pub role: String, // "admin" | "viewer" | "agent"
    pub iat: i64,     // issued at (unix timestamp)
    pub exp: i64,     // expiry (unix timestamp)
    pub nbf: i64,     // not before (unix timestamp)
    pub jti: String,  // unique token ID (UUID v4, prevents replay)
}

/// Token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    pub secret: String,       // from AITP_JWT_SECRET env var
    pub expiry_hours: i64,    // default: 24
    pub algorithm: Algorithm, // HS256
}

impl TokenConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let secret = std::env::var("AITP_JWT_SECRET").expect("AITP_JWT_SECRET must be set");

        // Enforce minimum secret length
        if secret.len() < 32 {
            panic!(
                "AITP_JWT_SECRET is too short ({} chars). \
                 Minimum 32 characters required. \
                 Generate one with: openssl rand -base64 64",
                secret.len()
            );
        }

        Ok(Self {
            secret,
            expiry_hours: std::env::var("AITP_TOKEN_EXPIRY_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24),
            algorithm: Algorithm::HS256,
        })
    }
}

/// Create a signed JWT for an authenticated org
pub fn create_token(
    config: &TokenConfig,
    org_id: &str,
    org_name: &str,
    email: &str,
    role: &str,
) -> anyhow::Result<String> {
    let now = Utc::now().timestamp();

    let claims = AitpClaims {
        sub: org_id.to_string(),
        org_id: org_id.to_string(),
        org_name: org_name.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        iat: now,
        exp: now + (config.expiry_hours * 3600),
        nbf: now,
        jti: uuid::Uuid::new_v4().to_string(),
    };

    let token = encode(
        &Header::new(config.algorithm),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )?;

    Ok(token)
}

/// Validate an incoming JWT and return its claims
/// Returns Err for expired, invalid signature, or malformed tokens
pub fn validate_token(config: &TokenConfig, token: &str) -> anyhow::Result<AitpClaims> {
    let mut validation = Validation::new(config.algorithm);
    validation.validate_exp = true; // always check expiry
    validation.validate_nbf = true; // always check not-before
    validation.leeway = 0; // no clock skew tolerance

    let token_data = decode::<AitpClaims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )
    .map_err(|e| anyhow::anyhow!("Invalid token: {}", e))?;

    Ok(token_data.claims)
}

/// Axum extractor — extracts AitpClaims from Authorization: Bearer header.
#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for AitpClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Auth("Missing authorization header".into()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(AppError::Auth(
                "Authorization header must be 'Bearer <token>'".into(),
            ));
        }

        let token = &auth_header[7..];

        validate_token(&state.config.token_config, token)
            .map_err(|e| AppError::Auth(format!("Invalid or expired token: {}", e)))
    }
}

/// Compatibility wrapper for OrgId (legacy)
pub struct OrgId(pub String);

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for OrgId {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Delegate to AitpClaims extractor
        let claims = AitpClaims::from_request_parts(parts, state).await?;
        Ok(OrgId(claims.org_id))
    }
}
