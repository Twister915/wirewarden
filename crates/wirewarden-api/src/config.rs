use std::env;

use thiserror::Error;

#[derive(Debug)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub jwt_secret: String,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
}

#[derive(Debug, Error)]
#[error("missing required environment variable: {var}")]
pub struct MissingEnvVar {
    var: &'static str,
}

fn require_env(var: &'static str) -> Result<String, MissingEnvVar> {
    env::var(var).map_err(|_| MissingEnvVar { var })
}

impl Config {
    pub fn from_env() -> Result<Self, MissingEnvVar> {
        Ok(Self {
            database_url: require_env("DATABASE_URL")?,
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            jwt_secret: require_env("JWT_SECRET")?,
            webauthn_rp_id: env::var("WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".to_string()),
            webauthn_rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
        })
    }
}
