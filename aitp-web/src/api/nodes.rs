use crate::{auth::OrgId, db::models::*, error::AppError, state::AppState};
use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/nodes/servers", get(list_servers).post(create_server))
        .route("/api/nodes/servers/:id", delete(delete_server))
        .route("/api/nodes/clients", get(list_clients).post(create_client))
        .route("/api/nodes/clients/:id", delete(delete_client))
}

async fn list_servers(
    OrgId(org_id): OrgId,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ServerNode>>, AppError> {
    let servers = state.db.get_servers(&org_id).await?;
    Ok(Json(servers))
}

async fn create_server(
    OrgId(org_id): OrgId,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateServerReq>,
) -> Result<Json<ServerNode>, AppError> {
    // Generate an Ed25519 identity for this node just conceptually
    // In practice, keys are saved on disk, but we record the generated pubkey here.
    let node = ServerNode {
        id: Uuid::new_v4().to_string(),
        org_id,
        name: req.name,
        listen_address: req.listen_address.unwrap_or_else(|| "0.0.0.0".into()),
        listen_port: req.listen_port.unwrap_or(9999) as i64,
        entity_id: Uuid::new_v4().to_string(), // In real AITP this is derived from pubkey
        public_key: "dummy_pub_key".into(),
        private_key_path: "/data/keys/dummy.pem".into(),
        status: "offline".into(),
        client_count: 0,
        session_count: 0,
        last_seen: None,
        created_at: chrono::Utc::now().timestamp(),
    };

    state.db.create_server(node.clone()).await?;
    Ok(Json(node))
}

async fn delete_server(
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = state.db.delete_server(&org_id, &id).await?;
    if rows == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "success": true })))
}

async fn list_clients(
    OrgId(org_id): OrgId,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ClientNode>>, AppError> {
    let clients = state.db.get_clients(&org_id).await?;
    Ok(Json(clients))
}

async fn create_client(
    OrgId(org_id): OrgId,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateClientReq>,
) -> Result<Json<ClientNode>, AppError> {
    let node = ClientNode {
        id: Uuid::new_v4().to_string(),
        org_id,
        name: req.name,
        entity_id: Uuid::new_v4().to_string(),
        public_key: "dummy_pub_key".into(),
        private_key_path: "/data/keys/dummy.pem".into(),
        allowed_intents: serde_json::to_string(&req.allowed_intents).unwrap_or_default(),
        trust_score: 128,
        session_count: 0,
        blocked_count: 0,
        last_seen: None,
        created_at: chrono::Utc::now().timestamp(),
    };

    state.db.create_client(node.clone()).await?;
    Ok(Json(node))
}

async fn delete_client(
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = state.db.delete_client(&org_id, &id).await?;
    if rows == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "success": true })))
}
