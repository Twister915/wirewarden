// Copyright (C) 2025 Joseph Sacchini
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::*;

use crate::config::Config;
use crate::db::user::UserStore;
use crate::db::webauthn::ChallengeStore;
use crate::error::ApiError;
use crate::extract::AuthUser;

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

/// Called from within the `/api/auth` scope — all paths are relative to it.
pub fn configure(auth_scope: &mut web::ServiceConfig) {
    auth_scope
        .service(
            web::scope("/passkey")
                .route("/register/begin", web::post().to(register_begin))
                .route("/register/finish", web::post().to(register_finish))
                .route("/login/begin", web::post().to(login_begin))
                .route("/login/finish", web::post().to(login_finish)),
        )
        .service(web::resource("/passkeys").route(web::get().to(list_passkeys)))
        .service(
            web::resource("/passkeys/{id}")
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
        .start_passkey_registration(
            auth.user_id,
            &user.username,
            &user.display_name,
            Some(exclude),
        )
        .map_err(|e| {
            tracing::error!(error = %e, "webauthn registration start failed");
            ApiError::Internal
        })?;

    let state_json = serde_json::to_value(&reg_state).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize reg state");
        ApiError::Internal
    })?;

    let session_id = Uuid::new_v4();
    challenges
        .insert(session_id, state_json)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to store registration challenge");
            ApiError::Internal
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "publicKey": ccr.public_key,
        "session_id": session_id,
    })))
}

#[derive(Debug, Deserialize)]
pub struct RegisterFinishRequest {
    pub session_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[tracing::instrument(skip(body, webauthn, challenges))]
async fn register_finish(
    auth: AuthUser,
    body: web::Json<RegisterFinishRequest>,
    store: web::Data<UserStore>,
    webauthn: web::Data<Webauthn>,
    challenges: web::Data<ChallengeStore>,
) -> Result<HttpResponse, ApiError> {
    let state_json = challenges
        .take(body.session_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to fetch registration challenge");
            ApiError::Internal
        })?
        .ok_or(ApiError::Validation(
            "no pending registration challenge".into(),
        ))?;

    let reg_state: PasskeyRegistration = serde_json::from_value(state_json).map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize reg state");
        ApiError::Internal
    })?;

    let passkey = webauthn
        .finish_passkey_registration(&body.credential, &reg_state)
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
        .add_passkey(auth.user_id, "Passkey", cred_id, &pk_bytes, 0, None, None)
        .await?;

    tracing::info!(user_id = %auth.user_id, "passkey registered");

    Ok(HttpResponse::Created().json(serde_json::json!({ "status": "ok" })))
}

#[tracing::instrument(skip(webauthn, challenges))]
async fn login_begin(
    webauthn: web::Data<Webauthn>,
    challenges: web::Data<ChallengeStore>,
) -> Result<HttpResponse, ApiError> {
    let (rcr, auth_state) = webauthn.start_discoverable_authentication().map_err(|e| {
        tracing::error!(error = %e, "webauthn discoverable auth start failed");
        ApiError::Internal
    })?;

    let state_json = serde_json::to_value(&auth_state).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize auth state");
        ApiError::Internal
    })?;

    let session_id = Uuid::new_v4();
    challenges
        .insert(session_id, state_json)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to store auth challenge");
            ApiError::Internal
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "publicKey": rcr.public_key,
        "session_id": session_id,
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
    let session_id: Uuid = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or(ApiError::Validation("missing session_id".into()))?;

    let credential: PublicKeyCredential = serde_json::from_value(
        body.get("credential").cloned().unwrap_or_default(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to parse credential");
        ApiError::Validation("invalid credential".into())
    })?;

    // The userHandle in the credential response contains the user UUID that was
    // set during passkey registration. Extract it to look up the user's keys.
    let user_handle = credential
        .response
        .user_handle
        .as_ref()
        .ok_or(ApiError::Validation("credential missing userHandle".into()))?;
    let user_id: Uuid = Uuid::from_slice(user_handle.as_ref()).map_err(|e| {
        tracing::error!(error = %e, "invalid userHandle in credential");
        ApiError::InvalidCredentials
    })?;

    let state_json = challenges
        .take(session_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to fetch auth challenge");
            ApiError::Internal
        })?
        .ok_or(ApiError::Validation("no pending auth challenge".into()))?;

    let auth_state: DiscoverableAuthentication =
        serde_json::from_value(state_json).map_err(|e| {
            tracing::error!(error = %e, "failed to deserialize auth state");
            ApiError::Internal
        })?;

    // Look up the user's passkeys to verify against
    let db_passkeys = store.get_passkeys(user_id).await?;
    let creds: Vec<DiscoverableKey> = db_passkeys
        .iter()
        .filter_map(|p| {
            serde_json::from_slice::<Passkey>(&p.public_key)
                .ok()
                .map(DiscoverableKey::from)
        })
        .collect();

    if creds.is_empty() {
        return Err(ApiError::InvalidCredentials);
    }

    let auth_result = webauthn
        .finish_discoverable_authentication(&credential, auth_state, &creds)
        .map_err(|e| {
            tracing::error!(error = %e, "webauthn discoverable auth finish failed");
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
