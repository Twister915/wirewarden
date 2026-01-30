use actix_web::dev::Payload;
use actix_web::web::Data;
use actix_web::{FromRequest, HttpRequest};
use std::future::{Ready, ready};
use uuid::Uuid;

use crate::auth::{Claims, validate_token};
use crate::config::Config;
use crate::error::ApiError;

#[derive(Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub claims: Claims,
}

impl FromRequest for AuthUser {
    type Error = ApiError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(extract_auth(req))
    }
}

fn extract_auth(req: &HttpRequest) -> Result<AuthUser, ApiError> {
    let config = req
        .app_data::<Data<Config>>()
        .ok_or(ApiError::Internal)?;

    let cookie = req.cookie("token").ok_or(ApiError::Unauthorized)?;
    let claims = validate_token(cookie.value(), &config.jwt_secret)?;

    Ok(AuthUser {
        user_id: claims.sub,
        claims,
    })
}
