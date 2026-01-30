use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonToml {
    #[serde(default)]
    pub servers: Vec<ServerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerEntry {
    pub api_host: String,
    pub api_token: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),

    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("failed to serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("duplicate api token: {0}")]
    DuplicateToken(String),
}

pub async fn load(path: &Path) -> Result<DaemonToml, ConfigError> {
    debug!(path = %path.display(), "loading config");

    match tokio::fs::read_to_string(path).await {
        Ok(contents) => {
            let config: DaemonToml = toml::from_str(&contents)?;
            info!(
                path = %path.display(),
                server_count = config.servers.len(),
                "loaded config"
            );
            for entry in &config.servers {
                debug!(
                    api_host = %entry.api_host,
                    "registered server"
                );
            }
            Ok(config)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(path = %path.display(), "config file not found, starting with empty config");
            Ok(DaemonToml { servers: vec![] })
        }
        Err(e) => Err(ConfigError::Read(e)),
    }
}

pub async fn save(path: &Path, config: &DaemonToml) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let contents = toml::to_string_pretty(config)?;
    tokio::fs::write(path, contents).await?;
    info!(
        path = %path.display(),
        server_count = config.servers.len(),
        "saved config"
    );
    Ok(())
}

pub fn validate_new_entry(
    config: &DaemonToml,
    entry: &ServerEntry,
) -> Result<(), ConfigError> {
    for existing in &config.servers {
        if existing.api_token == entry.api_token {
            warn!("api token already registered for another server");
            return Err(ConfigError::DuplicateToken(entry.api_token.clone()));
        }
    }
    debug!(
        api_host = %entry.api_host,
        "new entry validated"
    );
    Ok(())
}

/// Assign interface names (wg0, wg1, ...) to each server entry in order.
pub fn assign_interfaces(config: &DaemonToml) -> Vec<(&ServerEntry, String)> {
    config
        .servers
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let name = format!("wg{i}");
            debug!(interface = %name, api_host = %entry.api_host, "assigned interface");
            (entry, name)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn sample_config() -> DaemonToml {
        DaemonToml {
            servers: vec![ServerEntry {
                api_host: "https://vpn.example.com".into(),
                api_token: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
            }],
        }
    }

    #[test]
    fn round_trip_toml() {
        let config = sample_config();
        let serialized = toml::to_string_pretty(&config).unwrap();
        let parsed: DaemonToml = toml::from_str(&serialized).unwrap();
        assert_eq!(config.servers.len(), parsed.servers.len());
        assert_eq!(config.servers[0], parsed.servers[0]);
    }

    #[test]
    fn parse_empty_file() {
        let parsed: DaemonToml = toml::from_str("").unwrap();
        assert!(parsed.servers.is_empty());
    }

    #[test_case("bbbbbbbb", Ok(()); "unique entry")]
    #[test_case("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Err("duplicate token"); "duplicate token")]
    fn validate_entry(token: &str, expected: Result<(), &str>) {
        let config = sample_config();
        let entry = ServerEntry {
            api_host: "https://vpn2.example.com".into(),
            api_token: token.into(),
        };
        let result = validate_new_entry(&config, &entry);
        match expected {
            Ok(()) => assert!(result.is_ok()),
            Err(_) => assert!(result.is_err()),
        }
    }

    #[test]
    fn assign_interfaces_sequential() {
        let config = DaemonToml {
            servers: vec![
                ServerEntry {
                    api_host: "a".into(),
                    api_token: "a".into(),
                },
                ServerEntry {
                    api_host: "b".into(),
                    api_token: "b".into(),
                },
            ],
        };
        let assignments = assign_interfaces(&config);
        assert_eq!(assignments[0].1, "wg0");
        assert_eq!(assignments[1].1, "wg1");
    }
}
