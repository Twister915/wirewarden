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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::vpn::{self, VpnStore};
use crate::error::ApiError;
use crate::extract::AuthUser;

#[derive(Debug, Deserialize)]
struct CreateClientRequest {
    network_id: Uuid,
    name: String,
}

#[derive(Debug, Serialize)]
struct ClientResponse {
    id: Uuid,
    network_id: Uuid,
    name: String,
    public_key: String,
    address_offset: i32,
    address: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

async fn build_response(
    store: &VpnStore,
    client: vpn::WgClient,
) -> Result<ClientResponse, ApiError> {
    let key = store.get_key(client.key_id).await?;
    let network = store
        .get_network(client.network_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let address = vpn::compute_address(&network, client.address_offset);

    Ok(ClientResponse {
        id: client.id,
        network_id: client.network_id,
        name: client.name,
        public_key: key.public_key,
        address_offset: client.address_offset,
        address: address.to_string(),
        created_at: client.created_at,
        updated_at: client.updated_at,
    })
}

async fn create_client(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    body: web::Json<CreateClientRequest>,
) -> Result<HttpResponse, ApiError> {
    let key = store.create_key().await?;

    let client = store
        .create_client(body.network_id, &body.name, key.id)
        .await?;

    let resp = build_response(&store, client).await?;
    Ok(HttpResponse::Created().json(resp))
}

async fn get_client(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let client = store.get_client(id).await?.ok_or(ApiError::NotFound)?;
    let resp = build_response(&store, client).await?;
    Ok(HttpResponse::Ok().json(resp))
}

async fn delete_client(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let client = store.get_client(id).await?.ok_or(ApiError::NotFound)?;
    store.delete_client(id).await?;
    store.delete_key(client.key_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn list_clients(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let network_id = path.into_inner();
    let network = store.get_network(network_id).await?.ok_or(ApiError::NotFound)?;
    let clients = store.list_clients_by_network(network_id).await?;

    let key_ids: Vec<_> = clients.iter().map(|c| c.key_id).collect();
    let keys = store.get_keys_batch(&key_ids).await?;

    let resp: Vec<_> = clients
        .into_iter()
        .map(|c| {
            let key = &keys[&c.key_id];
            let address = vpn::compute_address(&network, c.address_offset);
            ClientResponse {
                id: c.id,
                network_id: c.network_id,
                name: c.name,
                public_key: key.public_key.clone(),
                address_offset: c.address_offset,
                address: address.to_string(),
                created_at: c.created_at,
                updated_at: c.updated_at,
            }
        })
        .collect();
    Ok(HttpResponse::Ok().json(resp))
}

#[derive(Debug, Deserialize)]
struct ConfigQuery {
    #[serde(default)]
    forward_internet: bool,
}

async fn client_config(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
    query: web::Query<ConfigQuery>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let client = store.get_client(id).await?.ok_or(ApiError::NotFound)?;
    let key = store.get_key(client.key_id).await?;

    let snapshot = store.load_network_snapshot(client.network_id).await?;

    // Load client keys into snapshot keys map
    let mut snapshot = snapshot;
    for srv in &snapshot.servers {
        if !snapshot.keys.contains_key(&srv.key_id) {
            let k = store.get_key(srv.key_id).await?;
            snapshot.keys.insert(k.id, k);
        }
    }

    let config = client.wg_quick_config(&key, &snapshot, query.forward_internet);

    Ok(HttpResponse::Ok().json(serde_json::json!({ "config": config })))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/api/clients")
            .route(web::post().to(create_client)),
    )
    .service(
        web::resource("/api/clients/{id}")
            .route(web::get().to(get_client))
            .route(web::delete().to(delete_client)),
    )
    .service(
        web::resource("/api/clients/{id}/config")
            .route(web::get().to(client_config)),
    )
    ;
}
