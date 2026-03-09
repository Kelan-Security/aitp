use axum::{
    extract::{Path, State},
    routing::{get, put},
    Json, Router,
};
use std::sync::Arc;

use crate::auth::OrgId;
use crate::db::models::*;
use crate::error::AppError;
use crate::identity::crypto;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/entities", get(list_entities).post(create_entity))
        .route("/api/entities/:id", get(get_entity).delete(delete_entity))
        .route("/api/entities/:id/quarantine", put(quarantine_entity))
        .route("/api/entities/:id/release", put(release_entity))
}

async fn list_entities(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
) -> Result<Json<Vec<Entity>>, AppError> {
    let entities = state.db.get_entities(&org_id).await?;
    Ok(Json(entities))
}

async fn create_entity(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Json(req): Json<CreateEntityReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Generate Ed25519 keypair
    let (sk_bytes, pk_bytes) = crypto::generate_keypair();
    let entity_id = crypto::entity_id_from_pubkey(&pk_bytes);
    let public_key_hex = hex::encode(pk_bytes);
    let private_key_hex = hex::encode(sk_bytes);

    let allowed_intents = req.allowed_intents.unwrap_or_else(|| {
        vec![
            "ModelInference".into(),
            "Heartbeat".into(),
            "DataSync".into(),
        ]
    });
    let allowed_json = serde_json::to_string(&allowed_intents).unwrap_or_default();

    let entity = Entity {
        id: entity_id.clone(),
        org_id: Some(org_id.clone()),
        name: req.name.clone(),
        entity_type: req.entity_type,
        public_key: public_key_hex.clone(),
        department: req.department,
        clearance_level: req.clearance_level.unwrap_or(0) as i64,
        allowed_intents: allowed_json,
        trust_score_avg: 128.0,
        session_count: 0,
        blocked_count: 0,
        quarantined: 0,
        last_seen: None,
        enrolled_at: chrono::Utc::now().timestamp(),
    };

    state.db.create_entity(entity).await?;

    let _ = state
        .db
        .insert_audit(
            &org_id,
            "EntityRegistered",
            "info",
            Some(&entity_id),
            None,
            &format!("Entity '{}' registered", req.name),
            "{}",
        )
        .await;

    state.hub.log(
        "INFO",
        &format!("Entity '{}' registered ({})", req.name, &entity_id[..12]),
    );

    Ok(Json(serde_json::json!({
        "entity_id": entity_id,
        "public_key": public_key_hex,
        "private_key": private_key_hex,
        "message": "Entity registered. Store the private key securely — it cannot be retrieved later."
    })))
}

async fn get_entity(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entity = state
        .db
        .get_entity(&id)
        .await
        .map_err(|_| AppError::NotFound)?;

    // Get recent sessions for this entity
    let sessions = state
        .db
        .get_sessions(entity.org_id.as_deref().unwrap_or(""), None, 20)
        .await
        .unwrap_or_default();

    let entity_sessions: Vec<_> = sessions
        .into_iter()
        .filter(|s| s.source_entity_id == id || s.dest_entity_id == id)
        .collect();

    Ok(Json(serde_json::json!({
        "entity": entity,
        "recent_sessions": entity_sessions,
    })))
}

async fn quarantine_entity(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let affected = state.db.quarantine_entity(&id).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }

    let _ = state
        .db
        .insert_audit(
            &org_id,
            "EntityQuarantined",
            "warning",
            Some(&id),
            None,
            &format!("Entity {} quarantined by admin", id),
            "{}",
        )
        .await;

    state.hub.log(
        "WARN",
        &format!("Entity {} quarantined", &id[..12.min(id.len())]),
    );

    Ok(Json(
        serde_json::json!({ "status": "quarantined", "entity_id": id }),
    ))
}

async fn release_entity(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let affected = state.db.release_entity(&id).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }

    let _ = state
        .db
        .insert_audit(
            &org_id,
            "EntityReleased",
            "info",
            Some(&id),
            None,
            &format!("Entity {} released from quarantine", id),
            "{}",
        )
        .await;

    state.hub.log(
        "INFO",
        &format!(
            "Entity {} released from quarantine",
            &id[..12.min(id.len())]
        ),
    );

    Ok(Json(
        serde_json::json!({ "status": "released", "entity_id": id }),
    ))
}

async fn delete_entity(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let affected = state.db.delete_entity(&org_id, &id).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }

    state.hub.log(
        "WARN",
        &format!("Entity {} deleted", &id[..12.min(id.len())]),
    );

    Ok(Json(
        serde_json::json!({ "status": "deleted", "entity_id": id }),
    ))
}
