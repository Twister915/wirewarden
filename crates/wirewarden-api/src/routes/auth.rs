use actix_web::{web, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{clear_auth_cookie, create_token, set_auth_cookie};
use crate::config::Config;
use crate::db::user::{User, UserStore};
use crate::error::ApiError;
use crate::extract::AuthUser;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl From<&User> for UserResponse {
    fn from(u: &User) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            email: u.email.clone(),
            created_at: u.created_at,
        }
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/me", web::get().to(me))
            .route("/forgot-password", web::post().to(forgot_password))
            .route("/reset-password", web::post().to(reset_password)),
    );
}

#[tracing::instrument(skip(body, store))]
async fn register(
    body: web::Json<RegisterRequest>,
    store: web::Data<UserStore>,
) -> Result<HttpResponse, ApiError> {
    if body.username.is_empty() || body.password.is_empty() || body.email.is_empty() {
        return Err(ApiError::Validation("missing required fields".into()));
    }

    let user = store
        .create(&body.username, &body.display_name, &body.email, &body.password)
        .await?;

    tracing::info!(user_id = %user.id, username = %user.username, "user registered");

    Ok(HttpResponse::Created().json(UserResponse::from(&user)))
}

#[tracing::instrument(skip(body, store, config))]
async fn login(
    body: web::Json<LoginRequest>,
    store: web::Data<UserStore>,
    config: web::Data<Config>,
) -> Result<HttpResponse, ApiError> {
    let user = store
        .get_by_username(&body.username)
        .await?
        .ok_or(ApiError::InvalidCredentials)?;

    if !store.verify_password(&user, &body.password)? {
        tracing::info!(username = %body.username, "login failed: invalid password");
        return Err(ApiError::InvalidCredentials);
    }

    let token = create_token(user.id, &config.jwt_secret)?;
    tracing::info!(user_id = %user.id, "login success");

    Ok(HttpResponse::Ok()
        .cookie(set_auth_cookie(&token))
        .json(UserResponse::from(&user)))
}

#[tracing::instrument(skip_all)]
async fn logout(_auth: AuthUser) -> HttpResponse {
    HttpResponse::Ok()
        .cookie(clear_auth_cookie())
        .json(serde_json::json!({ "status": "ok" }))
}

#[tracing::instrument(skip(store))]
async fn me(
    auth: AuthUser,
    store: web::Data<UserStore>,
) -> Result<HttpResponse, ApiError> {
    let user = store
        .get_by_id(auth.user_id)
        .await?
        .ok_or(ApiError::UserNotFound)?;

    Ok(HttpResponse::Ok().json(UserResponse::from(&user)))
}

#[tracing::instrument(skip(body, store))]
async fn forgot_password(
    body: web::Json<ForgotPasswordRequest>,
    store: web::Data<UserStore>,
) -> Result<HttpResponse, ApiError> {
    // Always return 200 to prevent email enumeration
    if let Ok(Some(user)) = store.get_by_email(&body.email).await {
        match store.set_reset_token(user.id).await {
            Ok(token) => {
                tracing::info!(user_id = %user.id, reset_token = %token, "password reset token generated");
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to set reset token");
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "If that email exists, a reset link has been sent."
    })))
}

#[tracing::instrument(skip(body, store))]
async fn reset_password(
    body: web::Json<ResetPasswordRequest>,
    store: web::Data<UserStore>,
) -> Result<HttpResponse, ApiError> {
    if body.password.is_empty() {
        return Err(ApiError::Validation("password required".into()));
    }

    let user = store
        .consume_reset_token(&body.token)
        .await?
        .ok_or(ApiError::InvalidResetToken)?;

    store.update_password(user.id, &body.password).await?;
    tracing::info!(user_id = %user.id, "password reset completed");

    Ok(HttpResponse::Ok().json(serde_json::json!({ "status": "ok" })))
}
