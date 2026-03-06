use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use crate::{state::AppState, error::AppError};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn create_token(org_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let claims = Claims {
        sub: org_id.to_string(),
        exp,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

pub fn validate_token(token: Option<&str>, secret: &str) -> Option<String> {
    let token = token?;
    let mut validation = Validation::default();
    validation.set_required_spec_claims(&["exp", "sub"]);
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .map(|data| data.claims.sub)
        .ok()
}

pub struct OrgId(pub String);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for OrgId {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get("Authorization")
            .and_then(|val| val.to_str().ok())
            .ok_or_else(|| AppError::Auth("Missing authorization header".into()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(AppError::Auth("Invalid authorization header".into()));
        }

        let token = &auth_header[7..];
        let org_id = validate_token(Some(token), &state.config.jwt_secret)
            .ok_or_else(|| AppError::Auth("Invalid token".into()))?;

        Ok(OrgId(org_id))
    }
}
