use crate::{auth::OrgId, db::models::*, error::AppError, state::AppState};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;

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
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e.to_string())))?
        .to_string();

    let org = Organization {
        id: Uuid::new_v4().to_string(),
        name: req.org_name,
        email: req.email.clone(),
        password_hash: hash,
        industry: req.industry,
        gemini_api_key_enc: req.gemini_api_key.clone(),
        claude_api_key_enc: None,
        openai_api_key_enc: None,
        ai_provider: if req.gemini_api_key.is_some() {
            "gemini".into()
        } else {
            "rules".into()
        },
        ai_model: "gemini-2.5-flash-preview-05-20".into(),
        trust_mode: "hybrid".into(),
        created_at: chrono::Utc::now().timestamp(),
        last_login: Some(chrono::Utc::now().timestamp()),
    };

    state.db.create_org(org.clone()).await?;
    let token = crate::auth::create_token(&org.id, &state.config.jwt_secret)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Json(AuthResp { token, org }))
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

    let is_valid = match PasswordHash::new(&org.password_hash) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .is_ok(),
        Err(_) => false,
    };

    if !is_valid {
        return Err(AppError::Auth("Invalid credentials".into()));
    }

    state.db.update_org_login(&org.id).await?;
    let token = crate::auth::create_token(&org.id, &state.config.jwt_secret)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Json(AuthResp { token, org }))
}

async fn me(
    OrgId(org_id): OrgId,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Organization>, AppError> {
    let org = state.db.get_org_by_id(&org_id).await?;
    Ok(Json(org))
}
