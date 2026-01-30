use actix_web::cookie::time::Duration;
use actix_web::cookie::{Cookie, SameSite};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
    pub iat: i64,
}

#[tracing::instrument(skip(secret))]
pub fn create_token(user_id: Uuid, secret: &str) -> Result<String, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        sub: user_id,
        exp: now + 86_400, // 24h
        iat: now,
    };

    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create JWT");
        ApiError::Internal
    })
}

#[tracing::instrument(skip(token, secret))]
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, ApiError> {
    jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| ApiError::Unauthorized)
}

pub fn set_auth_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("token", token.to_owned())
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(86_400))
        .finish()
}

pub fn clear_auth_cookie() -> Cookie<'static> {
    Cookie::build("token", "")
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::ZERO)
        .finish()
}
