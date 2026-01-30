use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};

use crate::db::user::UserStoreError;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("unauthorized")]
    Unauthorized,

    #[error("user not found")]
    UserNotFound,

    #[error("username already taken")]
    DuplicateUsername,

    #[error("email already taken")]
    DuplicateEmail,

    #[error("invalid reset token")]
    InvalidResetToken,

    #[error("reset token expired")]
    ResetTokenExpired,

    #[error("validation error: {0}")]
    Validation(String),

    #[error("internal server error")]
    Internal,
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentials | Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::UserNotFound => StatusCode::NOT_FOUND,
            Self::DuplicateUsername | Self::DuplicateEmail => StatusCode::CONFLICT,
            Self::InvalidResetToken | Self::ResetTokenExpired | Self::Validation(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .json(serde_json::json!({ "error": self.to_string() }))
    }
}

impl From<UserStoreError> for ApiError {
    fn from(err: UserStoreError) -> Self {
        match err {
            UserStoreError::DuplicateUsername => Self::DuplicateUsername,
            UserStoreError::DuplicateEmail => Self::DuplicateEmail,
            UserStoreError::TokenExpired => Self::ResetTokenExpired,
            UserStoreError::PasswordHash | UserStoreError::Database(_) => {
                tracing::error!(error = %err, "store error");
                Self::Internal
            }
        }
    }
}
