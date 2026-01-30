use std::env;

use thiserror::Error;

#[derive(Debug)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub jwt_secret: String,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    pub wg_key_secret: [u8; 32],
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {var}")]
    MissingEnvVar { var: &'static str },

    #[error("WG_KEY_SECRET must be exactly 64 hex characters (32 bytes)")]
    InvalidKeySecret,
}

fn require_env(var: &'static str) -> Result<String, ConfigError> {
    env::var(var).map_err(|_| ConfigError::MissingEnvVar { var })
}

fn parse_hex_32(hex: &str) -> Result<[u8; 32], ConfigError> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(ConfigError::InvalidKeySecret);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ConfigError::InvalidKeySecret)?;
    }
    Ok(out)
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let wg_key_hex = require_env("WG_KEY_SECRET")?;
        let wg_key_secret = parse_hex_32(&wg_key_hex)?;

        Ok(Self {
            database_url: require_env("DATABASE_URL")?,
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            jwt_secret: require_env("JWT_SECRET")?,
            webauthn_rp_id: env::var("WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".to_string()),
            webauthn_rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
            wg_key_secret,
        })
    }
}
