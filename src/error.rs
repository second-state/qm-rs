use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub type AppResult<T> = Result<T, AppError>;

/// Application-wide error type. Handlers return `Result<_, AppError>` and use
/// `?` on database / template / IO operations.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("database pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("template error: {0}")]
    Template(#[from] tera::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// The actor is known but not entitled to the resource. Distinct from
    /// `NotFound` so the audit log can tell "no such thing" from "not yours".
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// A command hit a `deny` rule in the resolved command policy.
    #[error("denied: {0}")]
    Denied(String),

    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn denied(msg: impl Into<String>) -> Self {
        Self::Denied(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Forbidden(_) | AppError::Denied(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "request failed");
        }
        (status, self.to_string()).into_response()
    }
}
