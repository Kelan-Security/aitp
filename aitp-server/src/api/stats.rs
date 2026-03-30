use axum::{extract::State, routing::get, Json, Router};
use std::sync::Arc;

use crate::auth::OrgId;
// Explicit imports to avoid unused warnings

use crate::error::AppError;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/stats", get(stats))
}

async fn stats(
    State(state): State<Arc<AppState>>,
    OrgId(_org_id): OrgId,
) -> Result<Json<serde_json::Value>, AppError> {
    let uptime = state.start_time.elapsed().as_secs();
    let stats = state.db.get_stats(uptime).await?;

    let ebpf_stats = state.enforcer.stats().await.unwrap_or_default();

    let mut resp = serde_json::to_value(&stats).unwrap();
    resp["ebpf_packets_total"] = serde_json::json!(ebpf_stats.packets_total);
    resp["ebpf_packets_dropped"] = serde_json::json!(ebpf_stats.packets_dropped);
    resp["ebpf_active_permits"] = serde_json::json!(ebpf_stats.active_permits);
    resp["ebpf_enforcement_mode"] = serde_json::json!(format!("{:?}", ebpf_stats.mode));

    let license = crate::license::ActiveLicense::get();
    resp["license"] = serde_json::json!({
        "tier": format!("{:?}", license.tier),
        "org_name": license.org_name,
        "node_limit": license.max_nodes,
        "expires_in_days": license.days_until_expiry(),
        "features": license.features.iter().map(|f| format!("{:?}", f)).collect::<Vec<_>>(),
    });

    // Zero-trust server attestation: expose the server's cryptographic entity ID and algorithm.
    // Clients can pin this value to detect server spoofing or MitM substitution.
    resp["server_identity"] = serde_json::json!({
        "entity_id": state.server_identity.entity_id_hex(),
        "algorithm": format!("{:?}", state.server_identity.algorithm),
    });

    Ok(Json(resp))
}
