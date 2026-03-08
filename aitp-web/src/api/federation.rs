use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    auth::OrgId,
    federation::{FederatedTrustToken, FederatedTrustTokenSigned},
    state::AppState,
};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/federation/orgs", get(list_orgs).post(register_org))
        .route("/api/federation/tokens/issue", post(issue_token))
        .route("/api/federation/tokens/verify", post(verify_token))
        .route("/api/federation/sessions", get(list_sessions))
}

#[derive(Deserialize)]
pub struct RegisterOrgReq {
    remote_org_id: String,
    remote_org_name: String,
    remote_root_pubkey: String,
    federation_level: String,
    allowed_intents: Vec<String>,
}

async fn register_org(
    State(state): State<Arc<AppState>>,
    OrgId(user_id): OrgId,
    Json(payload): Json<RegisterOrgReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let allowed_intents_json =
        serde_json::to_string(&payload.allowed_intents).unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO federated_orgs (
            id, org_id, remote_org_id, remote_org_name, remote_root_pubkey, 
            federation_level, allowed_intents, enabled, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(payload.remote_org_id)
    .bind(payload.remote_org_name)
    .bind(payload.remote_root_pubkey)
    .bind(payload.federation_level)
    .bind(allowed_intents_json)
    .bind(Utc::now().timestamp())
    .execute(state.db.inner())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "success" })),
    ))
}

#[derive(sqlx::FromRow)]
struct FedOrgRow {
    id: String,
    remote_org_id: String,
    remote_org_name: String,
    remote_root_pubkey: String,
    federation_level: String,
    allowed_intents: String,
    enabled: i64,
}

async fn list_orgs(
    State(state): State<Arc<AppState>>,
    OrgId(user_id): OrgId,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let orgs = sqlx::query_as::<_, FedOrgRow>(
        r#"
        SELECT id, remote_org_id, remote_org_name, remote_root_pubkey, 
               federation_level, allowed_intents, enabled
        FROM federated_orgs
        WHERE org_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(state.db.inner())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let out: Vec<_> = orgs.into_iter().map(|o| {
        serde_json::json!({
            "id": o.id,
            "remote_org_id": o.remote_org_id,
            "remote_org_name": o.remote_org_name,
            "remote_root_pubkey": o.remote_root_pubkey,
            "federation_level": o.federation_level,
            "allowed_intents": serde_json::from_str::<Vec<String>>(&o.allowed_intents).unwrap_or_default(),
            "enabled": o.enabled == 1
        })
    }).collect();

    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct IssueTokenReq {
    source_entity_id: String,
    dest_org_id: String,
    allowed_intents: Vec<String>,
    trust_floor: u8,
    ttl_seconds: i64,
}

fn get_org_root_key(org_id: &str) -> SigningKey {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"federation_root_seed");
    hasher.update(org_id.as_bytes());
    let result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    SigningKey::from_bytes(&seed)
}

#[derive(sqlx::FromRow)]
struct OrgNameRow {
    name: String,
}

async fn issue_token(
    State(state): State<Arc<AppState>>,
    OrgId(user_id): OrgId,
    Json(payload): Json<IssueTokenReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_rec = sqlx::query_as::<_, OrgNameRow>("SELECT name FROM organizations WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(state.db.inner())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Org not found".to_string()))?;

    let now = Utc::now().timestamp();
    let claims = FederatedTrustToken {
        version: 1,
        source_org_id: user_id.clone(),
        source_org_name: org_rec.name,
        source_entity_id: payload.source_entity_id,
        dest_org_id: payload.dest_org_id,
        allowed_intents: payload.allowed_intents,
        trust_floor: payload.trust_floor,
        issued_at: now,
        expires_at: now + payload.ttl_seconds,
        policy_hash: "sha256-dummy-hash".to_string(),
    };

    let claims_json = serde_json::to_string(&claims).unwrap();
    let signing_key = get_org_root_key(&user_id);
    let signature: Signature = signing_key.sign(claims_json.as_bytes());

    let signed_token = FederatedTrustTokenSigned {
        claims,
        signature: signature.to_bytes(),
        signing_key_id: "root-key-1".to_string(),
    };

    Ok((StatusCode::CREATED, Json(signed_token)))
}

#[derive(Deserialize)]
pub struct VerifyTokenReq {
    token: FederatedTrustTokenSigned,
}

#[derive(sqlx::FromRow)]
struct FedOrgVerifyRow {
    remote_root_pubkey: String,
    federation_level: String,
}

async fn verify_token(
    State(state): State<Arc<AppState>>,
    OrgId(user_id): OrgId,
    Json(payload): Json<VerifyTokenReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let claims = &payload.token.claims;

    let fed_org = sqlx::query_as::<_, FedOrgVerifyRow>(
        "SELECT remote_root_pubkey, federation_level FROM federated_orgs WHERE org_id = ? AND remote_org_id = ?"
    )
    .bind(user_id)
    .bind(&claims.source_org_id)
    .fetch_optional(state.db.inner())
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error".to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Federated Organization not trusted".to_string()))?;

    let pk_bytes = hex::decode(&fed_org.remote_root_pubkey)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid pubkey format".to_string()))?;
    if pk_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "Invalid pubkey length".to_string()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let verify_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid pubkey".to_string()))?;

    let claims_json = serde_json::to_string(claims).unwrap();
    let sig = Signature::from_bytes(&payload.token.signature);

    if verify_key.verify(claims_json.as_bytes(), &sig).is_err() {
        return Err((StatusCode::UNAUTHORIZED, "Invalid Signature".to_string()));
    }

    if Utc::now().timestamp() > claims.expires_at {
        return Err((StatusCode::UNAUTHORIZED, "Token expired".to_string()));
    }

    Ok(Json(serde_json::json!({
        "status": "verified",
        "federation_level": fed_org.federation_level
    })))
}

#[derive(sqlx::FromRow)]
struct FedSessionRow {
    id: String,
    remote_org_id: String,
    federation_level: String,
    client_entity_id: String,
    created_at: i64,
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    OrgId(user_id): OrgId,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let sessions = sqlx::query_as::<_, FedSessionRow>(
        r#"
        SELECT s.id, fs.remote_org_id, fs.federation_level, s.client_entity_id, fs.created_at
        FROM federated_sessions fs
        JOIN sessions s ON fs.session_id = s.id
        WHERE fs.local_org_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(state.db.inner())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let out: Vec<_> = sessions
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "session_id": s.id,
                "remote_org_id": s.remote_org_id,
                "federation_level": s.federation_level,
                "client_entity_id": s.client_entity_id,
                "created_at": s.created_at,
            })
        })
        .collect();

    Ok(Json(out))
}
