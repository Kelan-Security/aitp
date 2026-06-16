use crate::state::AppState;
use axum::{extract::State, routing::get, Json, Router};
use serde_json::json;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/status", get(status_handler))
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // Collect stats from the DB
    let mut classical = 0;
    let mut hybrid = 0;
    let mut pq = 0;

    // We would need a DB method to count algorithms.
    let count = state.db.get_crypto_stats().await.unwrap_or_default();

    for (alg, c) in count {
        match alg.as_str() {
            "Classical" => classical = c,
            "HybridPQ" => hybrid = c,
            "PostQuantum" => pq = c,
            _ => {}
        }
    }

    let total = classical + hybrid + pq;
    let percent = if total > 0 {
        ((hybrid + pq) as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let p1 = state.config.advertise_pq;

    Json(json!({
        "server_algorithm": "HybridPQ",
        "min_required": format!("{:?}", state.config.min_crypto_algorithm),
        "pq_advertised": p1,
        "entities": {
            "total": total,
            "classical_only": classical,
            "hybrid_pq": hybrid,
            "post_quantum": pq,
        },
        "pq_migration_percent": percent,
        "fips_203_status": "NIST standardised Aug 2024 (ML-KEM-768)",
        "fips_204_status": "NIST standardised Aug 2024 (ML-DSA-65)",
        "quantum_safe": percent >= 100.0,
        "recommendation": if classical > 0 {
            format!("{} entities still using classical-only crypto. Update their kelan-agent to v0.4+", classical)
        } else {
            "All entities are using post-quantum cryptography.".to_string()
        }
    }))
}
