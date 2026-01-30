use reqwest::Client;
use thiserror::Error;
use tracing::{debug, info, warn};
use wirewarden_types::daemon::DaemonConfig;

use crate::config::ServerEntry;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("server returned {status}: {body}")]
    ServerError { status: u16, body: String },

    #[error("unauthorized (401) — token may be revoked")]
    Unauthorized,

    #[error("not found (404) — server may be deleted")]
    NotFound,
}

impl ApiError {
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::NotFound)
    }
}

#[tracing::instrument(skip(client, entry), fields(api_host = %entry.api_host))]
pub async fn fetch_config(
    client: &Client,
    entry: &ServerEntry,
) -> Result<DaemonConfig, ApiError> {
    let url = format!("{}/api/daemon/config", entry.api_host.trim_end_matches('/'));

    debug!(url = %url, "fetching daemon config from API");

    let resp = client
        .get(&url)
        .bearer_auth(&entry.api_token)
        .send()
        .await?;

    let status = resp.status().as_u16();
    debug!(status, "received API response");

    match status {
        200 => {
            let config: DaemonConfig = resp.json().await?;
            info!(
                server_name = %config.server.name,
                network = %config.network.name,
                peer_count = config.peers.len(),
                listen_port = config.server.listen_port,
                address = %config.server.address,
                "fetched config successfully"
            );
            Ok(config)
        }
        401 => {
            warn!("API returned 401 — token may be revoked");
            Err(ApiError::Unauthorized)
        }
        404 => {
            warn!("API returned 404 — server may be deleted");
            Err(ApiError::NotFound)
        }
        _ => {
            let body = resp.text().await.unwrap_or_default();
            warn!(status, body = %body, "API returned unexpected status");
            Err(ApiError::ServerError { status, body })
        }
    }
}
