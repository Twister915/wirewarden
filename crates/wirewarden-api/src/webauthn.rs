use sqlx::PgPool;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

use crate::config::Config;

pub fn build_webauthn(config: &Config) -> Webauthn {
    let rp_origin =
        Url::parse(&config.webauthn_rp_origin).expect("invalid WEBAUTHN_RP_ORIGIN URL");

    WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin)
        .expect("failed to build Webauthn")
        .rp_name("wirewarden")
        .build()
        .expect("failed to finalize Webauthn")
}

/// PostgreSQL-backed store for WebAuthn challenge state with a 5-minute TTL.
#[derive(Debug, Clone)]
pub struct ChallengeStore {
    pool: PgPool,
}

impl ChallengeStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        session_id: Uuid,
        state: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO webauthn_challenges (session_id, state) \
             VALUES ($1, $2) \
             ON CONFLICT (session_id) DO UPDATE SET state = $2, created_at = now()",
        )
        .bind(session_id)
        .bind(&state)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// SELECT + DELETE in one query, returning `None` if missing or older than 5 minutes.
    pub async fn take(&self, session_id: Uuid) -> Result<Option<serde_json::Value>, sqlx::Error> {
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "DELETE FROM webauthn_challenges \
             WHERE session_id = $1 AND created_at > now() - interval '5 minutes' \
             RETURNING state",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(state,)| state))
    }

    /// Delete rows older than 5 minutes.
    pub async fn cleanup(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM webauthn_challenges WHERE created_at < now() - interval '5 minutes'",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
