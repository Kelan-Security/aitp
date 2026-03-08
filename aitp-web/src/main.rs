use axum::{routing::get, Router};
use dotenvy::dotenv;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::Instant;
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};

mod api;
mod auth;
mod bridge;
mod db;
mod error;
mod sentinel;
mod state;
mod ws;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    // Configuration
    let config = state::AppConfig {
        jwt_secret: std::env::var("AITP_JWT_SECRET")
            .unwrap_or_else(|_| "dev_secret_key_12345".into()),
        http_port: std::env::var("PORT")
            .unwrap_or_else(|_| "3000".into())
            .parse()
            .unwrap_or(3000),
        db_path: std::env::var("AITP_DB_PATH").unwrap_or_else(|_| "sqlite:aitp.db".into()),
    };

    // Parse DB path
    let db_path_str = config
        .db_path
        .strip_prefix("sqlite:")
        .unwrap_or(&config.db_path);
    let db_path = std::path::Path::new(db_path_str);

    // Create parent directories if they don't exist
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Initialize Database
    if !db_path.exists() {
        std::fs::File::create(db_path)?;
    }

    let mut db_conn_str = config.db_path.clone();
    if !db_conn_str.starts_with("sqlite:") {
        db_conn_str = format!("sqlite:{}", db_conn_str);
    }

    // Add connection options to ensure it creates if missing
    let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect(&db_conn_str)
        .await?;

    db::migrations::run(&db_pool).await?;

    let sentinel_instance = sentinel::Sentinel::new();

    let app_state = Arc::new(state::AppState {
        db: db::DbPool::new(db_pool),
        hub: ws::WsHub::new(),
        start_time: Instant::now(),
        config: config.clone(),
        sentinel: sentinel_instance.clone(),
    });

    // Start background tasks (AITP bridge to WS Hub, stats broadcaster, etc.)
    bridge::start_background_tasks(app_state.clone()).await;

    // Start Sentinel autonomous network defense agent
    let s = app_state.clone();
    let sen = sentinel_instance.clone();
    tokio::spawn(async move {
        sentinel::run(s, sen).await;
    });

    // Build the Axum router
    // We serve the Vue frontend from the "dist" directory if it exists,
    // otherwise just the API. During development with Vite, Vite serves the frontend
    // on port 5173, and we proxy /api to this Axum backend on port 3000.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let mut app = Router::new()
        .nest("/", api::router())
        .route("/ws", get(ws::ws_handler))
        .with_state(app_state)
        .layer(cors);

    // Serve static files if dist exists, else static
    if PathBuf::from("dist").exists() {
        app = app.fallback_service(ServeDir::new("dist"));
    } else if PathBuf::from("static").exists() {
        app = app.fallback_service(ServeDir::new("static"));
    }

    let addr = format!("0.0.0.0:{}", config.http_port);
    tracing::info!("Starting AITP Web Master Backend on http://{}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
