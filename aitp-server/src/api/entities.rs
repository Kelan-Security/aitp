use axum::{
    extract::{Path, State},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::OrgId;
use crate::db::models::*;
use crate::error::AppError;
use crate::identity::crypto;
use crate::state::AppState;
use crate::trust::SessionContext;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/entities", get(list_entities).post(create_entity))
        .route("/api/entities/:id", get(get_entity).delete(delete_entity))
        .route("/api/entities/:id/quarantine", put(quarantine_entity))
        .route("/api/entities/:id/release", put(release_entity))
        .route("/api/entities/:id/test-session", post(test_session))
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
    let entities = state.db.get_entities(&org_id).await.unwrap_or_default();
    let current_count = entities.len() as u32;
    crate::license::ActiveLicense::get()
        .check_node_limit(current_count)
        .map_err(|e| AppError::LicenseError(e.to_string()))?;

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
            Some("{}"),
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

    // XDP BPF Map revocation
    if let Ok(bytes) = hex::decode(&id) {
        if bytes.len() == 32 {
            let prefix: [u8; 8] = bytes[..8].try_into().unwrap();
            if let Ok(revoked) = state.enforcer.revoke_entity(&prefix).await {
                tracing::warn!("Quarantine: {} XDP permits revoked", revoked);
            }
        }
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
            Some("{}"),
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
            Some("{}"),
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
#[derive(Deserialize)]
pub struct TestSessionReq {
    pub dest_entity_id: String,
    pub intent: String,
    pub bytes_tx: Option<u64>,
    pub simulate_lateral_movement: Option<bool>,
}

async fn test_session(
    State(state): State<Arc<AppState>>,
    OrgId(org_id): OrgId,
    Path(id): Path<String>,
    Json(req): Json<TestSessionReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    // 1. Resolve entities
    let source = state
        .db
        .get_entity(&id)
        .await
        .map_err(|_| AppError::NotFound)?;
    let dest = state
        .db
        .get_entity(&req.dest_entity_id)
        .await
        .map_err(|_| AppError::BadRequest("Destination entity not found".into()))?;

    // 2. Build context for trust evaluation
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let age_hours = (now - source.enrolled_at) as f64 / 3600.0;

    // Simulate flags
    let behavioral_flags = if req.simulate_lateral_movement.unwrap_or(false) {
        vec!["NewPeerInteraction".to_string()]
    } else if req.bytes_tx.unwrap_or(0) > 10_000_000 {
        vec!["ExfiltrationPattern".to_string()]
    } else {
        vec![]
    };

    let ctx = SessionContext {
        source_entity_id: id.clone(),
        org_id: org_id.clone(),
        source_entity_type: source.entity_type,
        source_department: source.department.clone(),
        source_clearance: source.clearance_level as u8,
        dest_entity_id: req.dest_entity_id.clone(),
        dest_entity_type: dest.entity_type.clone(),
        intent: req.intent.clone(),
        entity_age_hours: age_hours,
        session_count_24h: source.session_count as u32,
        avg_trust_score: source.trust_score_avg,
        known_peer: true,
        behavioral_flags: behavioral_flags.clone(),
        time_of_day_hour: 12,
    };

    // 3. Evaluate trust
    let result = state.trust_engine.evaluate(&ctx).await;

    // 3b. Publish event to Sentinel (non-blocking)
    let baseline_score = state.sentinel.get_baseline(&id).await.map(|b| b.avg_trust_score).unwrap_or(128.0);
    let is_new_peer = !state.sentinel.get_baseline(&id).await.map(|b| b.known_peers.contains(&req.dest_entity_id)).unwrap_or(false);
    
    let signal = crate::sentinel::SentinelEvent::classify(
        &req.intent,
        result.trust_score,
        baseline_score,
        is_new_peer,
        result.verdict.as_str(),
    );
    
    state.send_sentinel_event(crate::sentinel::SentinelEvent {
        entity_id:      id.clone(),
        org_id:         org_id.clone(),
        session_id:     session_id.clone(),
        dest_entity_id: req.dest_entity_id.clone(),
        intent:         req.intent.clone(),
        trust_score:    result.trust_score,
        verdict:        result.verdict.as_str().to_string(),
        bytes_tx:       req.bytes_tx.unwrap_or(0),
        occurred_at:    now,
        signal,
    });

    // XDP BPF Permit insertion
    use crate::enforcement::SessionPermit;
    use crate::protocol::IntentCode;
    use crate::trust::TrustVerdict;
    
    let source_bytes = hex::decode(&id).unwrap_or(vec![0; 32]);
    let dest_bytes = hex::decode(&req.dest_entity_id).unwrap_or(vec![0; 32]);
    
    if source_bytes.len() == 32 && dest_bytes.len() == 32 {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&source_bytes);
        let mut d_bytes = [0u8; 32];
        d_bytes.copy_from_slice(&dest_bytes);
        
        let numeric_intent = IntentCode::from_str_loose(&req.intent) as u16;
        let p_verdict = match result.verdict {
            TrustVerdict::Allow => 1,
            TrustVerdict::Monitor => 2,
            _ => 0,
        };
        
        let permit = SessionPermit::new(
            &s_bytes,
            &d_bytes,
            numeric_intent,
            result.trust_score,
            p_verdict,
            3600,
        );
        // Using a random session ID for testing XDP
        let test_session_id = rand::random::<u64>();
        let _ = state.enforcer.permit(test_session_id, permit).await;
    }

    // 4. Record the session in DB
    let session_id = uuid::Uuid::new_v4().to_string();
    let session = Session {
        id: session_id.clone(),
        org_id: org_id.clone(),
        source_entity_id: id.clone(),
        dest_entity_id: req.dest_entity_id.clone(),
        intent: req.intent.clone(),
        trust_score: result.trust_score as i64,
        verdict: result.verdict.as_str().to_string(),
        ai_reasoning: Some(result.reasoning.clone()),
        ai_latency_ms: Some(result.evaluation_ms),
        status: "Active".to_string(),
        bytes_tx: req.bytes_tx.unwrap_or(0) as i64,
        bytes_rx: 0,
        anomaly_flags: behavioral_flags.join(","),
        started_at: now,
        ended_at: None,
        close_reason: None,
    };
    state.db.create_session(session).await?;

    // 5. Broadcast event
    state.hub.broadcast(WsEvent::SessionNew {
        session_id: session_id.clone(),
        source_entity: source.name,
        dest_entity: dest.name,
        intent: ctx.intent,
        trust_score: result.trust_score,
        verdict: result.verdict.as_str().to_string(),
        ts: now,
    });

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "verdict": result.verdict.as_str(),
        "trust_score": result.trust_score,
        "reasoning": result.reasoning,
        "primary_risk": result.primary_risk,
        "evaluation_source": result.source
    })))
}
