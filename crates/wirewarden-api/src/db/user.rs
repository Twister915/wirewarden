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

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub password_hash: String,
    pub reset_token: Option<String>,
    pub reset_token_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserPasskey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub passkey_name: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub aaguid: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserStoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("username already taken")]
    DuplicateUsername,

    #[error("email already taken")]
    DuplicateEmail,

    #[error("password hashing failed")]
    PasswordHash,

    #[error("reset token expired")]
    TokenExpired,
}

type Result<T> = std::result::Result<T, UserStoreError>;

#[derive(Debug, Clone)]
pub struct UserStore {
    pool: PgPool,
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| UserStoreError::PasswordHash)
}

impl UserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[tracing::instrument(skip(self))]
    pub async fn is_empty(&self) -> Result<bool> {
        let row: (bool,) =
            sqlx::query_as("SELECT NOT EXISTS (SELECT 1 FROM users)")
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }

    #[tracing::instrument(skip(self, password))]
    pub async fn create(
        &self,
        username: &str,
        display_name: &str,
        email: &str,
        password: &str,
    ) -> Result<User> {
        let password_hash = hash_password(password)?;

        sqlx::query_as::<_, User>(
            "INSERT INTO users (username, display_name, email, password_hash)
             VALUES ($1, $2, $3, $4)
             RETURNING *",
        )
        .bind(username)
        .bind(display_name)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.constraint() == Some("users_username_key") => {
                UserStoreError::DuplicateUsername
            }
            sqlx::Error::Database(db_err) if db_err.constraint() == Some("users_email_key") => {
                UserStoreError::DuplicateEmail
            }
            _ => UserStoreError::Database(e),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_by_username(&self, username: &str) -> Result<Option<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self, password), fields(user_id = %user.id))]
    pub fn verify_password(&self, user: &User, password: &str) -> Result<bool> {
        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|_| UserStoreError::PasswordHash)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    #[tracing::instrument(skip(self, new_password))]
    pub async fn update_password(&self, id: Uuid, new_password: &str) -> Result<()> {
        let password_hash = hash_password(new_password)?;

        sqlx::query(
            "UPDATE users
             SET password_hash = $1, reset_token = NULL, reset_token_expires_at = NULL, updated_at = now()
             WHERE id = $2",
        )
        .bind(password_hash)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_reset_token(&self, id: Uuid) -> Result<String> {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        sqlx::query(
            "UPDATE users SET reset_token = $1, reset_token_expires_at = $2, updated_at = now()
             WHERE id = $3",
        )
        .bind(&token)
        .bind(expires_at)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(token)
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn consume_reset_token(&self, token: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE reset_token = $1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        let Some(user) = user else {
            return Ok(None);
        };

        if let Some(expires_at) = user.reset_token_expires_at {
            if expires_at < Utc::now() {
                return Err(UserStoreError::TokenExpired);
            }
        }

        sqlx::query(
            "UPDATE users SET reset_token = NULL, reset_token_expires_at = NULL, updated_at = now()
             WHERE id = $1",
        )
        .bind(user.id)
        .execute(&self.pool)
        .await?;

        Ok(Some(user))
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // --- Passkey operations ---

    #[tracing::instrument(skip(self, credential_id, public_key))]
    pub async fn add_passkey(
        &self,
        user_id: Uuid,
        name: &str,
        credential_id: &[u8],
        public_key: &[u8],
        sign_count: i64,
        transports: Option<&serde_json::Value>,
        aaguid: Option<Uuid>,
    ) -> Result<UserPasskey> {
        sqlx::query_as::<_, UserPasskey>(
            "INSERT INTO user_passkeys (user_id, passkey_name, credential_id, public_key, sign_count, transports, aaguid)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *",
        )
        .bind(user_id)
        .bind(name)
        .bind(credential_id)
        .bind(public_key)
        .bind(sign_count)
        .bind(transports)
        .bind(aaguid)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_passkeys(&self, user_id: Uuid) -> Result<Vec<UserPasskey>> {
        sqlx::query_as::<_, UserPasskey>(
            "SELECT * FROM user_passkeys WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self, credential_id))]
    pub async fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<UserPasskey>> {
        sqlx::query_as::<_, UserPasskey>(
            "SELECT * FROM user_passkeys WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn update_passkey_sign_count(&self, id: Uuid, sign_count: i64) -> Result<()> {
        sqlx::query("UPDATE user_passkeys SET sign_count = $1 WHERE id = $2")
            .bind(sign_count)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn rename_passkey(&self, id: Uuid, new_name: &str) -> Result<()> {
        sqlx::query("UPDATE user_passkeys SET passkey_name = $1 WHERE id = $2")
            .bind(new_name)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_passkey(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM user_passkeys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
