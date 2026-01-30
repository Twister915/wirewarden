use actix_web::dev::Payload;
use actix_web::web::Data;
use actix_web::{FromRequest, HttpRequest};
use futures::future::LocalBoxFuture;
use std::future::{Ready, ready};
use uuid::Uuid;

use crate::auth::{Claims, validate_token};
use crate::config::Config;
use crate::db::vpn::{VpnStore, WgServer};
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

#[derive(Debug)]
pub struct AuthServer(pub WgServer);

impl FromRequest for AuthServer {
    type Error = ApiError;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let store = req.app_data::<Data<VpnStore>>().cloned();
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        Box::pin(async move {
            let store = store.ok_or(ApiError::Internal)?;
            let header = auth_header.ok_or(ApiError::Unauthorized)?;
            let token = header
                .strip_prefix("Bearer ")
                .ok_or(ApiError::Unauthorized)?;

            let server = store
                .get_server_by_token(token)
                .await
                .map_err(|_| ApiError::Internal)?
                .ok_or(ApiError::Unauthorized)?;

            Ok(AuthServer(server))
        })
    }
}
