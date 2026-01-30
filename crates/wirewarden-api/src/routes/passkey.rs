use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs::Webauthn;

use crate::config::Config;
use crate::db::user::UserStore;
use crate::error::ApiError;
use crate::extract::AuthUser;
use crate::webauthn::ChallengeStore;

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginBeginRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct RenameRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth/passkey")
            .route("/register/begin", web::post().to(register_begin))
            .route("/register/finish", web::post().to(register_finish))
            .route("/login/begin", web::post().to(login_begin))
            .route("/login/finish", web::post().to(login_finish)),
    )
    .service(
        web::resource("/api/auth/passkeys")
            .route(web::get().to(list_passkeys)),
    )
    .service(
        web::resource("/api/auth/passkeys/{id}")
            .route(web::patch().to(rename_passkey))
            .route(web::delete().to(delete_passkey)),
    );
}

#[tracing::instrument(skip(webauthn, challenges))]
async fn register_begin(
    auth: AuthUser,
    store: web::Data<UserStore>,
    webauthn: web::Data<Webauthn>,
    challenges: web::Data<ChallengeStore>,
) -> Result<HttpResponse, ApiError> {
    let existing = store.get_passkeys(auth.user_id).await?;
    let exclude: Vec<CredentialID> = existing
        .iter()
        .map(|p| CredentialID::from(p.credential_id.clone()))
        .collect();

    let user = store
        .get_by_id(auth.user_id)
        .await?
        .ok_or(ApiError::UserNotFound)?;

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(auth.user_id, &user.username, &user.display_name, Some(exclude))
        .map_err(|e| {
            tracing::error!(error = %e, "webauthn registration start failed");
            ApiError::Internal
        })?;

    let state_json = serde_json::to_value(&reg_state).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize reg state");
        ApiError::Internal
    })?;

    let key = format!("reg:{}", auth.user_id);
    challenges.insert(key, state_json);

    Ok(HttpResponse::Ok().json(ccr))
}

#[tracing::instrument(skip(body, webauthn, challenges))]
async fn register_finish(
    auth: AuthUser,
    body: web::Json<RegisterPublicKeyCredential>,
    store: web::Data<UserStore>,
    webauthn: web::Data<Webauthn>,
    challenges: web::Data<ChallengeStore>,
) -> Result<HttpResponse, ApiError> {
    let key = format!("reg:{}", auth.user_id);
    let state_json = challenges
        .take(&key)
        .ok_or(ApiError::Validation("no pending registration challenge".into()))?;

    let reg_state: PasskeyRegistration = serde_json::from_value(state_json).map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize reg state");
        ApiError::Internal
    })?;

    let passkey = webauthn
        .finish_passkey_registration(&body, &reg_state)
        .map_err(|e| {
            tracing::error!(error = %e, "webauthn registration finish failed");
            ApiError::Validation("passkey registration failed".into())
        })?;

    let cred_id: &[u8] = passkey.cred_id().as_ref();
    let pk_bytes = serde_json::to_vec(&passkey).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize passkey");
        ApiError::Internal
    })?;

    store
        .add_passkey(
            auth.user_id,
            "Passkey",
            cred_id,
            &pk_bytes,
            0,
            None,
            None,
        )
        .await?;

    tracing::info!(user_id = %auth.user_id, "passkey registered");

    Ok(HttpResponse::Created().json(serde_json::json!({ "status": "ok" })))
}

#[tracing::instrument(skip(webauthn, challenges))]
async fn login_begin(
    body: web::Json<PasskeyLoginBeginRequest>,
    store: web::Data<UserStore>,
    webauthn: web::Data<Webauthn>,
    challenges: web::Data<ChallengeStore>,
) -> Result<HttpResponse, ApiError> {
    let user = store
        .get_by_username(&body.username)
        .await?
        .ok_or(ApiError::InvalidCredentials)?;

    let db_passkeys = store.get_passkeys(user.id).await?;
    if db_passkeys.is_empty() {
        return Err(ApiError::InvalidCredentials);
    }

    let passkeys: Vec<Passkey> = db_passkeys
        .iter()
        .filter_map(|p| serde_json::from_slice(&p.public_key).ok())
        .collect();

    if passkeys.is_empty() {
        return Err(ApiError::InvalidCredentials);
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            tracing::error!(error = %e, "webauthn auth start failed");
            ApiError::Internal
        })?;

    let state_json = serde_json::to_value(&auth_state).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize auth state");
        ApiError::Internal
    })?;

    let key = format!("auth:{}", user.id);
    challenges.insert(key.clone(), state_json);

    // Include user_id in response so the finish endpoint knows which challenge to look up
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "publicKey": rcr.public_key,
        "user_id": user.id,
    })))
}

#[tracing::instrument(skip(body, webauthn, challenges, config))]
async fn login_finish(
    body: web::Json<serde_json::Value>,
    store: web::Data<UserStore>,
    webauthn: web::Data<Webauthn>,
    challenges: web::Data<ChallengeStore>,
    config: web::Data<Config>,
) -> Result<HttpResponse, ApiError> {
    let user_id: Uuid = body
        .get("user_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or(ApiError::Validation("missing user_id".into()))?;

    let credential: PublicKeyCredential =
        serde_json::from_value(body.get("credential").cloned().unwrap_or_default()).map_err(
            |e| {
                tracing::error!(error = %e, "failed to parse credential");
                ApiError::Validation("invalid credential".into())
            },
        )?;

    let key = format!("auth:{user_id}");
    let state_json = challenges
        .take(&key)
        .ok_or(ApiError::Validation("no pending auth challenge".into()))?;

    let auth_state: PasskeyAuthentication =
        serde_json::from_value(state_json).map_err(|e| {
            tracing::error!(error = %e, "failed to deserialize auth state");
            ApiError::Internal
        })?;

    let auth_result = webauthn
        .finish_passkey_authentication(&credential, &auth_state)
        .map_err(|e| {
            tracing::error!(error = %e, "webauthn auth finish failed");
            ApiError::InvalidCredentials
        })?;

    // Update sign count
    let cred_id_bytes: &[u8] = auth_result.cred_id().as_ref();
    if let Ok(Some(db_passkey)) = store.get_passkey_by_credential_id(cred_id_bytes).await {
        let _ = store
            .update_passkey_sign_count(db_passkey.id, auth_result.counter() as i64)
            .await;
    }

    let user = store
        .get_by_id(user_id)
        .await?
        .ok_or(ApiError::UserNotFound)?;

    let token = crate::auth::create_token(user.id, &config.jwt_secret)?;
    tracing::info!(user_id = %user.id, "passkey login success");

    Ok(HttpResponse::Ok()
        .cookie(crate::auth::set_auth_cookie(&token))
        .json(crate::routes::auth::UserResponse::from(&user)))
}

#[tracing::instrument(skip(store))]
async fn list_passkeys(
    auth: AuthUser,
    store: web::Data<UserStore>,
) -> Result<HttpResponse, ApiError> {
    let passkeys = store.get_passkeys(auth.user_id).await?;
    let list: Vec<PasskeyInfo> = passkeys
        .iter()
        .map(|p| PasskeyInfo {
            id: p.id,
            name: p.passkey_name.clone(),
            created_at: p.created_at,
        })
        .collect();

    Ok(HttpResponse::Ok().json(list))
}

#[tracing::instrument(skip(store))]
async fn rename_passkey(
    auth: AuthUser,
    path: web::Path<Uuid>,
    body: web::Json<RenameRequest>,
    store: web::Data<UserStore>,
) -> Result<HttpResponse, ApiError> {
    let passkey_id = path.into_inner();

    // Verify ownership
    let passkeys = store.get_passkeys(auth.user_id).await?;
    if !passkeys.iter().any(|p| p.id == passkey_id) {
        return Err(ApiError::UserNotFound);
    }

    store.rename_passkey(passkey_id, &body.name).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "status": "ok" })))
}

#[tracing::instrument(skip(store))]
async fn delete_passkey(
    auth: AuthUser,
    path: web::Path<Uuid>,
    store: web::Data<UserStore>,
) -> Result<HttpResponse, ApiError> {
    let passkey_id = path.into_inner();

    let passkeys = store.get_passkeys(auth.user_id).await?;
    if !passkeys.iter().any(|p| p.id == passkey_id) {
        return Err(ApiError::UserNotFound);
    }

    store.delete_passkey(passkey_id).await?;
    tracing::info!(user_id = %auth.user_id, passkey_id = %passkey_id, "passkey deleted");
    Ok(HttpResponse::Ok().json(serde_json::json!({ "status": "ok" })))
}
