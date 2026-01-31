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

use actix_web::{web, HttpResponse};

use crate::db::vpn::{self, VpnStore};
use crate::error::ApiError;
use crate::extract::AuthServer;
use wirewarden_types::daemon::{DaemonConfig, DaemonNetworkInfo, DaemonPeer, DaemonServerInfo};

async fn daemon_config(
    AuthServer(server): AuthServer,
    store: web::Data<VpnStore>,
) -> Result<HttpResponse, ApiError> {
    let network = store
        .get_network(server.network_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    let server_key = store.get_key(server.key_id).await?;
    let address = vpn::compute_address(&network, server.address_offset);
    let cidr = network.cidr_ip.to_string();

    let server_info = DaemonServerInfo {
        id: server.id,
        name: server.name.clone(),
        private_key: server_key.private_key,
        public_key: server_key.public_key,
        address: format!("{address}/{}", network.prefix()),
        listen_port: server.endpoint_port,
    };

    let network_info = DaemonNetworkInfo {
        id: network.id,
        name: network.name.clone(),
        cidr,
        persistent_keepalive: network.persistent_keepalive,
    };

    let (servers, clients) = futures::future::try_join(
        store.list_servers_by_network(server.network_id),
        store.list_clients_by_network(server.network_id),
    )
    .await?;

    let other_servers: Vec<_> = servers.iter().filter(|s| s.id != server.id).collect();

    let key_ids: Vec<_> = other_servers
        .iter()
        .map(|s| s.key_id)
        .chain(clients.iter().map(|c| c.key_id))
        .collect();
    let keys = store.get_keys_batch(&key_ids).await?;

    let route_lists = futures::future::try_join_all(
        other_servers.iter().map(|s| store.list_routes_by_server(s.id)),
    )
    .await?;
    let server_routes: std::collections::HashMap<_, _> = other_servers
        .iter()
        .map(|s| s.id)
        .zip(route_lists)
        .collect();

    let mut peers = Vec::with_capacity(key_ids.len());

    for other in &other_servers {
        let key = &keys[&other.key_id];
        let ip = vpn::compute_address(&network, other.address_offset);
        let endpoint = other
            .endpoint_host
            .as_ref()
            .map(|h| format!("{h}:{}", other.endpoint_port));

        let mut allowed_ips = vec![format!("{ip}/32")];
        if let Some(routes) = server_routes.get(&other.id) {
            for route in routes {
                allowed_ips.push(route.route_cidr.to_string());
            }
        }

        peers.push(DaemonPeer {
            public_key: key.public_key.clone(),
            allowed_ips,
            endpoint,
        });
    }

    for client in &clients {
        let key = &keys[&client.key_id];
        let ip = vpn::compute_address(&network, client.address_offset);
        peers.push(DaemonPeer {
            public_key: key.public_key.clone(),
            allowed_ips: vec![format!("{ip}/32")],
            endpoint: None,
        });
    }

    let config = DaemonConfig {
        server: server_info,
        network: network_info,
        peers,
    };

    Ok(HttpResponse::Ok().json(config))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/api/daemon/config")
            .route(web::get().to(daemon_config)),
    );
}
