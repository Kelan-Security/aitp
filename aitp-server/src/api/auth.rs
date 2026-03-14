use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;

use crate::auth::{self, AitpClaims};
use crate::db::models::*;
use crate::error::AppError;
use crate::state::AppState;
use argon2::PasswordHasher;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/signin", post(signin))
        .route("/api/auth/me", get(me))
}

async fn signup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignupReq>,
) -> Result<Json<AuthResp>, AppError> {
    // Check if email already exists
    if state.db.get_org_by_email(&req.email).await.is_ok() {
        return Err(AppError::Conflict("Email already registered".into()));
    }

    // Hash password
    let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
    let password_hash = argon2::Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| AppError::BadRequest(format!("Failed to hash password: {}", e)))?
        .to_string();

    let org_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    let org = Organisation {
        id: org_id.clone(),
        name: req.org_name,
        email: req.email,
        password_hash,
        gemini_api_key_enc: None,
        trust_mode: "hybrid".to_string(),
        created_at: now,
    };

    state.db.create_org(org.clone()).await?;

    // Log to audit chain
    let _ = state
        .db
        .insert_audit(
            &org_id,
            "OrgCreated",
            "info",
            None,
            None,
            &format!("Organisation '{}' created", org.name),
            Some("{}"),
        )
        .await;

    state.hub.log(
        "INFO",
        &format!("New organisation registered: {}", org.name),
    );

    let token = auth::create_token(
        &state.config.token_config,
        &org_id,
        &org.name,
        &org.email,
        "admin",
    )
    .map_err(|e| AppError::BadRequest(format!("Failed to create token: {}", e)))?;

    let expires_at = (chrono::Utc::now()
        + chrono::Duration::hours(state.config.token_config.expiry_hours))
    .to_rfc3339();

    Ok(Json(AuthResp {
        token,
        org,
        expires_at,
    }))
}

async fn signin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SigninReq>,
) -> Result<Json<AuthResp>, AppError> {
    let org = state
        .db
        .get_org_by_email(&req.email)
        .await
        .map_err(|_| AppError::Auth("Invalid credentials".into()))?;

    // Verify password
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed_hash = PasswordHash::new(&org.password_hash)
        .map_err(|_| AppError::Auth("Invalid credentials".into()))?;

    argon2::Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::Auth("Invalid credentials".into()))?;

    let token = auth::create_token(
        &state.config.token_config,
        &org.id,
        &org.name,
        &org.email,
        "admin",
    )
    .map_err(|e| AppError::BadRequest(format!("Failed to create token: {}", e)))?;

    let expires_at = (chrono::Utc::now()
        + chrono::Duration::hours(state.config.token_config.expiry_hours))
    .to_rfc3339();

    state
        .hub
        .log("INFO", &format!("Organisation '{}' signed in", org.name));

    Ok(Json(AuthResp {
        token,
        org,
        expires_at,
    }))
}

async fn me(
    State(state): State<Arc<AppState>>,
    claims: AitpClaims, // Use AitpClaims directly
) -> Result<Json<Organisation>, AppError> {
    let org = state.db.get_org_by_id(&claims.org_id).await?;
    Ok(Json(org))
}
