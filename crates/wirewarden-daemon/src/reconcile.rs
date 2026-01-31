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

use std::collections::{HashMap, HashSet};
use std::path::Path;

use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use tracing::{debug, error, info, warn};
use wirewarden_types::daemon::DaemonConfig;

use crate::api;
use crate::config::{self, DaemonToml};
use crate::netlink::{IFACE_PREFIX, Platform, PlatformError};

/// Tracks previously applied configs per interface so we can skip no-op cycles.
#[derive(Debug, Default)]
pub struct ReconcileState {
    /// Last applied config per interface name.
    applied: HashMap<String, DaemonConfig>,
    /// Maps private key (base64) to assigned interface name for stable naming.
    assignments: HashMap<String, String>,
}

impl ReconcileState {
    /// Return all interface names currently managed by this state.
    pub fn interface_names(&self) -> impl Iterator<Item = &str> {
        self.assignments.values().map(|s| s.as_str())
    }
}

/// Allocate the lowest available `wwgN` name, skipping names in `taken`.
fn next_interface_name(taken: &HashSet<String>) -> String {
    (0..)
        .map(|i| format!("{IFACE_PREFIX}{i}"))
        .find(|name| !taken.contains(name))
        .unwrap()
}

/// Run one reconciliation cycle for all configured servers.
///
/// For each server entry:
/// 1. Fetch the desired config from the API
/// 2. Match to an existing interface by private key, or allocate a new name
/// 3. Apply it to the WireGuard interface
/// 4. If the API returns 401/404, tear down the interface and remove the entry
/// 5. Remove orphaned wirewarden-managed interfaces
#[tracing::instrument(skip_all)]
pub async fn reconcile_all<P: Platform>(
    client: &Client,
    config_path: &Path,
    config: &mut DaemonToml,
    state: &mut ReconcileState,
) {
    let server_count = config.servers.len();
    info!(server_count, "starting reconciliation cycle");

    if server_count == 0 {
        debug!("no servers to reconcile");
        return;
    }

    // Phase 1: Discover existing wirewarden-managed interfaces and their keys.
    let existing = match P::list_managed_interfaces().await {
        Ok(map) => map,
        Err(e) => {
            error!(error = %e, "failed to list managed interfaces, skipping cycle");
            return;
        }
    };

    // Build a reverse map: private_key -> interface_name from live system state.
    let key_to_iface: HashMap<&str, &str> = existing
        .iter()
        .map(|(name, key)| (key.as_str(), name.as_str()))
        .collect();

    // Phase 2: Fetch configs and assign interface names.
    let mut fetched: Vec<(usize, DaemonConfig, String)> = Vec::new();
    let mut to_remove: Vec<usize> = Vec::new();
    let mut taken: HashSet<String> = HashSet::new();

    // Fetch all configs concurrently.
    let fetch_results: Vec<(usize, Result<DaemonConfig, api::ApiError>)> = config
        .servers
        .iter()
        .enumerate()
        .map(|(i, entry)| async move {
            debug!(
                api_host = %entry.api_host,
                "fetching config for server {}/{}",
                i + 1,
                server_count,
            );
            let result = api::fetch_config(client, entry).await;
            (i, result)
        })
        .collect::<FuturesUnordered<_>>()
        .collect()
        .await;

    // Assign interfaces: prefer existing interface with matching private key.
    for (i, result) in fetch_results {
        match result {
            Ok(daemon_config) => {
                let key = &daemon_config.server.private_key;

                // Check if there's an existing interface with this private key.
                let iface_name = if let Some(&name) = key_to_iface.get(key.as_str()) {
                    debug!(
                        interface = name,
                        server = %daemon_config.server.name,
                        "matched to existing interface by private key"
                    );
                    name.to_owned()
                } else if let Some(name) = state.assignments.get(key) {
                    // We assigned this key before but interface may not exist yet.
                    debug!(
                        interface = %name,
                        server = %daemon_config.server.name,
                        "reusing previous assignment"
                    );
                    name.clone()
                } else {
                    // Allocate a new name.
                    let name = next_interface_name(&taken);
                    debug!(
                        interface = %name,
                        server = %daemon_config.server.name,
                        "allocated new interface"
                    );
                    name
                };

                taken.insert(iface_name.clone());
                state.assignments.insert(key.clone(), iface_name.clone());
                fetched.push((i, daemon_config, iface_name));
            }
            Err(e) if e.is_gone() => {
                warn!(
                    api_host = %config.servers[i].api_host,
                    "server gone (401/404), will tear down"
                );
                to_remove.push(i);
            }
            Err(e) => {
                error!(
                    api_host = %config.servers[i].api_host,
                    error = %e,
                    "fetch failed, will retry next cycle"
                );
            }
        }
    }

    // Phase 3: Apply configs.
    let mut active_ifaces: HashSet<String> = HashSet::new();

    for (_, daemon_config, interface) in fetched {
        active_ifaces.insert(interface.clone());

        if state.applied.get(&interface) == Some(&daemon_config) {
            debug!(
                interface = interface.as_str(),
                server = %daemon_config.server.name,
                "config unchanged, skipping"
            );
            continue;
        }

        debug!(
            interface = interface.as_str(),
            server = %daemon_config.server.name,
            "applying config to interface"
        );
        let prev = state.applied.get(&interface).map(|c| c as &DaemonConfig);

        match P::apply_config(&interface, &daemon_config, prev).await {
            Ok(()) => {
                info!(
                    interface = interface.as_str(),
                    server = %daemon_config.server.name,
                    peer_count = daemon_config.peers.len(),
                    "interface configured successfully"
                );
                state.applied.insert(interface, daemon_config);
            }
            Err(e) => {
                error!(
                    interface = interface.as_str(),
                    error = %e,
                    "failed to apply config, will retry next cycle"
                );
            }
        }
    }

    // Phase 4: Clean up orphaned wirewarden-managed interfaces.
    for (name, _key) in &existing {
        if !active_ifaces.contains(name) {
            warn!(interface = %name, "removing orphaned managed interface");
            if let Err(e) = P::remove_interface(name).await {
                error!(interface = %name, error = %e, "failed to remove orphaned interface");
            }
            state.applied.remove(name);
            // Remove from assignments by value.
            state.assignments.retain(|_, v| v != name);
        }
    }

    // Phase 5: Remove gone server entries from config.
    if !to_remove.is_empty() {
        info!(
            count = to_remove.len(),
            "removing gone server entries from config"
        );
        for &i in to_remove.iter().rev() {
            let removed = config.servers.remove(i);
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
