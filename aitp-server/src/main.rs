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
    // 1. Load .env first so JWT_SECRET is available for generate-token
    dotenv().ok();

    // 2. Handle CLI subcommands BEFORE connecting to the database
    //    generate-token only needs the JWT secret from .env, no DB required.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "generate-token" {
        let mut org_id = "test-org".to_string();
        let mut org_name = "Test Org".to_string();
        let mut email = "admin@test.com".to_string();
        let mut role = "admin".to_string();

        for i in 2..args.len() {
            match args[i].as_str() {
                "--org-id" => {
                    if i + 1 < args.len() {
                        org_id = args[i + 1].clone();
                    }
                }
                "--org-name" => {
                    if i + 1 < args.len() {
                        org_name = args[i + 1].clone();
                    }
                }
                "--email" => {
                    if i + 1 < args.len() {
                        email = args[i + 1].clone();
                    }
                }
                "--role" => {
                    if i + 1 < args.len() {
                        role = args[i + 1].clone();
                    }
                }
                _ => {}
            }
        }
        return cmd_generate_token(&org_id, &org_name, &email, &role).await;
    }

    // 3. Init tracing (only needed for server mode)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aitp_server=info,tower_http=warn".into()),
        )
        .init();

    // 4. Load config
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

    let sentinel_instance = sentinel::Sentinel::new();
    let trust_engine = crate::trust::HybridTrustEngine::new(
        &app_config.gemini_api_key,
        &app_config.gemini_model,
        app_config.trust_alpha,
        &app_config.trust_mode,
    );

    let app_state = Arc::new(state::AppState {
        db: db::DbPool::new(db_pool),
        hub: ws::WsHub::new(),
        config: app_config.clone(),
        start_time: Instant::now(),
        sentinel: sentinel_instance.clone(),
        trust_engine,
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

    // 10. Start server
    let addr = format!("0.0.0.0:{}", app_config.http_port);
    tracing::info!("AITP Intelligence Core Server listening on http://{}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn cmd_generate_token(
    org_id: &str,
    org_name: &str,
    email: &str,
    role: &str,
) -> anyhow::Result<()> {
    let config = crate::auth::TokenConfig::from_env().expect("AITP_JWT_SECRET must be set in .env");

    let token = crate::auth::create_token(&config, org_id, org_name, email, role)
        .expect("Token generation failed");

    let expiry = chrono::Utc::now() + chrono::Duration::hours(config.expiry_hours);

    // Metadata to stderr
    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!("║           AITP JWT Token Generated                  ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprintln!("Org ID:   {}", org_id);
    eprintln!("Org Name: {}", org_name);
    eprintln!("Email:    {}", email);
    eprintln!("Role:     {}", role);
    eprintln!("Expires:  {} UTC", expiry.format("%Y-%m-%d %H:%M:%S"));

    eprintln!("\n-- Token (printed to stdout) --");
    // Raw token to stdout
    println!("{}", token);

    eprintln!("\n-- Shell Variable --");
    eprintln!("TOKEN=\"{}\"", token);
    eprintln!("\n-- REST Test --");
    eprintln!("curl -s http://localhost:3000/api/auth/me -H \"Authorization: Bearer $TOKEN\" | jq");
    eprintln!("\n-- WebSocket Test --");
    eprintln!("websocat \"ws://localhost:3000/ws?token=$TOKEN\"");
    eprintln!();

    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

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
