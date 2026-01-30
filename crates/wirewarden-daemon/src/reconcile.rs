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

use std::path::Path;

use reqwest::Client;
use tracing::{debug, error, info, warn};

use crate::api;
use crate::config::{self, DaemonToml, ServerEntry};
use crate::netlink::{Platform, PlatformError};

/// Run one reconciliation cycle for all configured servers.
///
/// For each server entry:
/// 1. Fetch the desired config from the API
/// 2. Apply it to the WireGuard interface
/// 3. If the API returns 401/404, tear down the interface and remove the entry
#[tracing::instrument(skip_all)]
pub async fn reconcile_all<P: Platform>(
    client: &Client,
    config_path: &Path,
    config: &mut DaemonToml,
    interfaces: &mut Vec<String>,
) {
    let server_count = config.servers.len();
    info!(server_count, "starting reconciliation cycle");

    if server_count == 0 {
        debug!("no servers to reconcile");
        return;
    }

    let mut to_remove: Vec<usize> = Vec::new();

    for (i, entry) in config.servers.iter().enumerate() {
        let interface = &interfaces[i];
        debug!(
            interface = %interface,
            api_host = %entry.api_host,
            "reconciling server {}/{server_count}",
            i + 1,
        );

        if let Err(e) = reconcile_one::<P>(client, entry, interface).await {
            if e.is_gone() {
                warn!(
                    interface = %interface,
                    api_host = %entry.api_host,
                    "server gone (401/404), tearing down interface"
                );
                if let Err(e) = P::remove_interface(interface).await {
                    error!(interface = %interface, error = %e, "failed to remove interface");
                }
                to_remove.push(i);
            } else {
                error!(
                    interface = %interface,
                    error = %e,
                    "reconciliation failed, will retry next cycle"
                );
            }
        }
    }

    if !to_remove.is_empty() {
        info!(count = to_remove.len(), "removing gone server entries from config");
        for &i in to_remove.iter().rev() {
            let removed = config.servers.remove(i);
            interfaces.remove(i);
            info!(
                api_host = %removed.api_host,
                "removed server entry from config"
            );
        }
        if let Err(e) = config::save(config_path, config).await {
            error!(error = %e, "failed to save updated config after removing entries");
        }
    }

    info!(
        server_count = config.servers.len(),
        "reconciliation cycle complete"
    );
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Api(#[from] api::ApiError),

    #[error(transparent)]
    Platform(#[from] PlatformError),
}

impl ReconcileError {
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Api(e) if e.is_gone())
    }
}

async fn reconcile_one<P: Platform>(
    client: &Client,
    entry: &ServerEntry,
    interface: &str,
) -> Result<(), ReconcileError> {
    let daemon_config = api::fetch_config(client, entry).await?;

    debug!(
        interface,
        server = %daemon_config.server.name,
        "applying config to interface"
    );
    P::apply_config(interface, &daemon_config).await?;

    info!(
        interface,
        server = %daemon_config.server.name,
        peer_count = daemon_config.peers.len(),
        "interface configured successfully"
    );
    Ok(())
}
