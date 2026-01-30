use actix_web::{web, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::vpn::{self, VpnStore};
use crate::error::ApiError;
use crate::extract::AuthUser;

#[derive(Debug, Deserialize)]
struct CreateServerRequest {
    network_id: Uuid,
    name: String,
    address_offset: i32,
    forwards_internet_traffic: bool,
    endpoint_host: Option<String>,
    endpoint_port: i32,
}

#[derive(Debug, Serialize)]
struct ServerResponse {
    id: Uuid,
    network_id: Uuid,
    name: String,
    public_key: String,
    api_token: String,
    address_offset: i32,
    address: String,
    forwards_internet_traffic: bool,
    endpoint_host: Option<String>,
    endpoint_port: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

async fn build_response(
    store: &VpnStore,
    server: vpn::WgServer,
    full_token: bool,
) -> Result<ServerResponse, ApiError> {
    let key = store.get_key(server.key_id).await?;
    let network = store
        .get_network(server.network_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let address = vpn::compute_address(&network, server.address_offset);

    let api_token = if full_token {
        server.api_token.clone()
    } else {
        redact_token(&server.api_token)
    };

    Ok(ServerResponse {
        id: server.id,
        network_id: server.network_id,
        name: server.name,
        public_key: key.public_key,
        api_token,
        address_offset: server.address_offset,
        address: address.to_string(),
        forwards_internet_traffic: server.forwards_internet_traffic,
        endpoint_host: server.endpoint_host,
        endpoint_port: server.endpoint_port,
        created_at: server.created_at,
        updated_at: server.updated_at,
    })
}

async fn create_server(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    body: web::Json<CreateServerRequest>,
) -> Result<HttpResponse, ApiError> {
    let key = store.create_key().await?;

    let server = store
        .create_server(
            body.network_id,
            &body.name,
            key.id,
            body.address_offset,
            body.forwards_internet_traffic,
            body.endpoint_host.as_deref(),
            body.endpoint_port,
        )
        .await?;

    let resp = build_response(&store, server, true).await?;
    Ok(HttpResponse::Created().json(resp))
}

async fn get_server(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let server = store.get_server(id).await?.ok_or(ApiError::NotFound)?;
    let resp = build_response(&store, server, false).await?;
    Ok(HttpResponse::Ok().json(resp))
}

async fn delete_server(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let server = store.get_server(id).await?.ok_or(ApiError::NotFound)?;
    store.delete_server(id).await?;
    store.delete_key(server.key_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

fn redact_token(token: &str) -> String {
    if token.len() > 8 {
        format!("{}…", &token[..8])
    } else {
        "…".into()
    }
}

async fn list_servers(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let network_id = path.into_inner();
    let network = store.get_network(network_id).await?.ok_or(ApiError::NotFound)?;
    let servers = store.list_servers_by_network(network_id).await?;

    let key_ids: Vec<_> = servers.iter().map(|s| s.key_id).collect();
    let keys = store.get_keys_batch(&key_ids).await?;

    let resp: Vec<_> = servers
        .into_iter()
        .map(|s| {
            let key = &keys[&s.key_id];
            let address = vpn::compute_address(&network, s.address_offset);
            ServerResponse {
                id: s.id,
                network_id: s.network_id,
                name: s.name,
                public_key: key.public_key.clone(),
                api_token: redact_token(&s.api_token),
                address_offset: s.address_offset,
                address: address.to_string(),
                forwards_internet_traffic: s.forwards_internet_traffic,
                endpoint_host: s.endpoint_host,
                endpoint_port: s.endpoint_port,
                created_at: s.created_at,
                updated_at: s.updated_at,
            }
        })
        .collect();
    Ok(HttpResponse::Ok().json(resp))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/api/servers")
            .route(web::post().to(create_server)),
    )
    .service(
        web::resource("/api/servers/{id}")
            .route(web::get().to(get_server))
            .route(web::delete().to(delete_server)),
    )
    .service(
        web::resource("/api/networks/{id}/servers")
            .route(web::get().to(list_servers)),
    );
}
