use std::sync::Arc;
use tokio::time::{interval, Duration};
use crate::state::AppState;

pub async fn start_background_tasks(state: Arc<AppState>) {
    // Task 1: Broadcast stats every 5 seconds to all connected clients
    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let uptime = state_clone.start_time.elapsed().as_secs();
            if let Ok(stats) = state_clone.db.get_stats(uptime).await {
                state_clone.hub.broadcast(crate::db::models::WsEvent::Stats {
                    active_sessions: stats.active_sessions,
                    avg_trust: stats.avg_trust_score,
                    blocked_today: stats.blocked_today,
                    ai_calls: stats.ai_calls_today,
                    uptime_secs: stats.uptime_seconds,
                });
            }
        }
    });

    // Task 2: A simulated AITP event bridge
    // In a fully integrated production environment, this would listen to
    // an mpsc channel from the `aitp-sdk` server instances or a local Redis pubsub
    // and broadcast those events directly to the WebSocket hub.
    // We already have `WsEvent` variants for SessionEstablished, SessionClosed, TrustEval, PacketFlow, etc.
    let state_clone2 = state.clone();
    tokio::spawn(async move {
        let mut sim_ticker = interval(Duration::from_secs(12));
        loop {
            sim_ticker.tick().await;
            // Simulated traffic flow just to keep the dashboard lively if no real AITP traffic is flowing
            state_clone2.hub.broadcast(crate::db::models::WsEvent::PacketFlow {
                session_id: "sim-session".into(),
                direction: "rx".into(),
                bytes: 1240,
                intent: "ModelInference".into(),
                trust: 190,
                ts: chrono::Utc::now().format("%H:%M:%S%.3f").to_string(),
            });
        }
    });
}
