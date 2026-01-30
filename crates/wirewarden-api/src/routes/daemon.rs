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
    let cidr = format!("{}/{}", network.cidr_ip, network.cidr_prefix);

    let server_info = DaemonServerInfo {
        id: server.id,
        name: server.name.clone(),
        private_key: server_key.private_key,
        public_key: server_key.public_key,
        address: format!("{address}/{}", network.cidr_prefix),
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

    let key_ids: Vec<_> = servers
        .iter()
        .filter(|s| s.id != server.id)
        .map(|s| s.key_id)
        .chain(clients.iter().map(|c| c.key_id))
        .collect();
    let keys = store.get_keys_batch(&key_ids).await?;

    let mut peers = Vec::with_capacity(key_ids.len());

    for other in servers.iter().filter(|s| s.id != server.id) {
        let key = &keys[&other.key_id];
        let ip = vpn::compute_address(&network, other.address_offset);
        let endpoint = other
            .endpoint_host
            .as_ref()
            .map(|h| format!("{h}:{}", other.endpoint_port));

        peers.push(DaemonPeer {
            public_key: key.public_key.clone(),
            allowed_ips: vec![format!("{ip}/32")],
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
