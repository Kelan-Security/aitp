use tokio::time::Instant;

#[derive(Clone)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub http_port: u16,
    pub db_path: String,
}

pub struct AppState {
    pub db: crate::db::DbPool,
    pub hub: crate::ws::WsHub,
    pub config: AppConfig,
    pub start_time: Instant,
    pub sentinel: std::sync::Arc<crate::sentinel::Sentinel>,
}
