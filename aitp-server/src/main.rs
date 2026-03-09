use axum::{routing::get, Router};
use dotenvy::dotenv;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{interval, Duration, Instant};
use tower_http::cors::{Any, CorsLayer};

mod api;
mod auth;
mod config;
mod db;
#[allow(dead_code)]
mod enforcement;
mod error;
#[allow(dead_code)]
mod identity;
#[allow(dead_code)]
mod protocol;
mod sentinel;
mod state;
#[allow(dead_code)]
mod trust;
mod ws;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Load .env
    dotenv().ok();

    // 2. Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aitp_server=info,tower_http=warn".into()),
        )
        .init();

    // 3. Load config
    let app_config = config::AppConfig::from_env();

    // 4. Connect SQLite, run migrations
    let db_path_str = &app_config.db_path;
    let db_path = std::path::Path::new(db_path_str);

    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    if !db_path.exists() {
        std::fs::File::create(db_path)?;
    }

    let mut conn_str = app_config.db_path.clone();
    if !conn_str.starts_with("sqlite:") {
        conn_str = format!("sqlite:{}", conn_str);
    }

    let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&conn_str)
        .await?;

    db::migrations::run(&db_pool).await?;

    // 5. Create AppState
    let sentinel_instance = sentinel::Sentinel::new();

    let app_state = Arc::new(state::AppState {
        db: db::DbPool::new(db_pool),
        hub: ws::WsHub::new(),
        config: app_config.clone(),
        start_time: Instant::now(),
        sentinel: sentinel_instance.clone(),
    });

    // 6. Start background tasks
    // a. Sentinel monitoring loop
    if app_config.sentinel_enabled {
        let s = app_state.clone();
        let sen = sentinel_instance.clone();
        tokio::spawn(async move {
            sentinel::run(s, sen).await;
        });
    }

    // b. Stats broadcaster — push stats to WS every 5 seconds
    {
        let s = app_state.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let uptime = s.start_time.elapsed().as_secs();
                if let Ok(stats) = s.db.get_stats(uptime).await {
                    s.hub.broadcast(db::models::WsEvent::Stats {
                        active_sessions: stats.active_sessions,
                        blocked_today: stats.blocked_today,
                        ai_calls: stats.ai_calls,
                        avg_trust: stats.avg_trust,
                        entities_online: stats.entities_online,
                        threats_detected_today: stats.threats_detected_today,
                        uptime_secs: stats.uptime_secs,
                    });
                }
            }
        });
    }

    // c. Session cleanup — expire old sessions every 60 seconds
    {
        let s = app_state.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                if let Ok(expired) = s.db.expire_old_sessions(3600).await {
                    if expired > 0 {
                        s.hub
                            .log("INFO", &format!("{} stale sessions expired", expired));
                    }
                }
            }
        });
    }

    // 7. Build Axum router
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .merge(api::router())
        .route("/ws", get(ws::ws_handler))
        .with_state(app_state.clone())
        .layer(cors);

    // 8. Print startup banner
    print_banner(&app_config);

    // 9. Start server
    let addr = format!("0.0.0.0:{}", app_config.http_port);
    tracing::info!("AITP Intelligence Core Server listening on http://{}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn print_banner(config: &config::AppConfig) {
    let banner = r#"

    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║              AITP INTELLIGENCE CORE SERVER                    ║
    ║              ═════════════════════════════                    ║
    ║                                                               ║
    ║    Adaptive Intent Transport Protocol — Security Gateway      ║
    ║    Identity-First • Intent-Bound • Zero-Trust                 ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝

"#;
    println!("{}", banner);
    println!("    Version:     0.3.0");
    println!("    Config:      {}", config.summary());
    println!("    Status:      ONLINE");
    println!();
}
