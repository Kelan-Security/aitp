use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Not found")]
    NotFound,

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Db(ref e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ),
            AppError::Auth(ref msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Internal(ref e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {}", e),
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string()),
            AppError::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Conflict(ref msg) => (StatusCode::CONFLICT, msg.clone()),
        };

        let body = Json(json!({ "error": error_message, "type": "error" }));
        (status, body).into_response()
    }
}
