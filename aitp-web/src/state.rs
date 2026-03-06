use tokio::time::Instant;

#[derive(Clone)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub http_port: u16,
    pub aitp_port: u16,
    pub db_path: String,
}

pub struct AppState {
    pub db: crate::db::DbPool,
    pub hub: crate::ws::WsHub,
    pub http: reqwest::Client,
    pub config: AppConfig,
    pub start_time: Instant,
}
