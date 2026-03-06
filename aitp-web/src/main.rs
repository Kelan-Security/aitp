use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio::time::Instant;
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};
use dotenvy::dotenv;

mod state;
mod error;
mod auth;
mod api;
mod ws;
mod db;
mod bridge;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    // Configuration
    let config = state::AppConfig {
        jwt_secret: std::env::var("AITP_JWT_SECRET").unwrap_or_else(|_| "dev_secret_key_12345".into()),
        http_port: std::env::var("PORT").unwrap_or_else(|_| "3000".into()).parse().unwrap_or(3000),
        aitp_port: std::env::var("AITP_UDP_PORT").unwrap_or_else(|_| "1414".into()).parse().unwrap_or(1414),
        db_path: std::env::var("AITP_DB_PATH").unwrap_or_else(|_| "sqlite:aitp.db".into()),
    };

    // Initialize Database
    if !std::path::Path::new("aitp.db").exists() {
        std::fs::File::create("aitp.db")?;
    }
    
    let db_pool = sqlx::SqlitePool::connect(&config.db_path).await?;
    db::migrations::run(&db_pool).await?;

    let app_state = Arc::new(state::AppState {
        db: db::DbPool::new(db_pool),
        hub: ws::WsHub::new(),
        http: reqwest::Client::new(),
        start_time: Instant::now(),
        config: config.clone(),
    });

    // Start background tasks (AITP bridge to WS Hub, stats broadcaster, etc.)
    bridge::start_background_tasks(app_state.clone()).await;

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

    // Serve static files if dist exists
    if PathBuf::from("dist").exists() {
        app = app.fallback_service(ServeDir::new("dist"));
    }

    let addr = format!("0.0.0.0:{}", config.http_port);
    tracing::info!("Starting AITP Web Master Backend on http://{}", addr);
    
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
