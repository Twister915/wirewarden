use std::net::IpAddr;

use actix_web::{web, HttpResponse};
use chrono::{DateTime, Utc};
use ipnetwork::{IpNetwork, Ipv4Network};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::vpn::VpnStore;
use crate::error::ApiError;
use crate::extract::AuthUser;

fn is_private_ipv4_network(net: Ipv4Network) -> bool {
    let ip = net.ip();
    ip.is_private() || ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127
}

fn validate_dns_servers(servers: &[String]) -> Result<(), ApiError> {
    for s in servers {
        s.parse::<IpAddr>()
            .map_err(|_| ApiError::Validation(format!("invalid DNS server IP: {s}")))?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CreateNetworkRequest {
    name: String,
    cidr: String,
    dns_servers: Vec<String>,
    #[serde(default = "default_keepalive")]
    persistent_keepalive: i32,
}

fn default_keepalive() -> i32 {
    25
}

#[derive(Debug, Serialize)]
struct NetworkResponse {
    id: Uuid,
    name: String,
    cidr: String,
    dns_servers: Vec<String>,
    persistent_keepalive: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl NetworkResponse {
    fn from_model(n: crate::db::vpn::Network) -> Self {
        let cidr = format!("{}/{}", n.cidr_ip, n.cidr_prefix);
        Self {
            id: n.id,
            name: n.name,
            cidr,
            dns_servers: n.dns_servers,
            persistent_keepalive: n.persistent_keepalive,
            created_at: n.created_at,
            updated_at: n.updated_at,
        }
    }
}

async fn list_networks(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
) -> Result<HttpResponse, ApiError> {
    let networks = store.list_networks().await?;
    let resp: Vec<_> = networks.into_iter().map(NetworkResponse::from_model).collect();
    Ok(HttpResponse::Ok().json(resp))
}

async fn create_network(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    body: web::Json<CreateNetworkRequest>,
) -> Result<HttpResponse, ApiError> {
    let cidr: IpNetwork = body
        .cidr
        .parse()
        .map_err(|_| ApiError::Validation("invalid CIDR".into()))?;

    if cidr.is_ipv6() {
        return Err(ApiError::Validation("IPv6 not supported".into()));
    }

    let v4 = match cidr {
        IpNetwork::V4(v4) => v4,
        _ => unreachable!(),
    };

    if !is_private_ipv4_network(v4) {
        return Err(ApiError::Validation("CIDR must be in a private IP range".into()));
    }

    validate_dns_servers(&body.dns_servers)?;

    let prefix = cidr.prefix() as i32;
    let network = store
        .create_network(&body.name, cidr, prefix, None, &body.dns_servers, body.persistent_keepalive)
        .await?;

    Ok(HttpResponse::Created().json(NetworkResponse::from_model(network)))
}

async fn get_network(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let network = store.get_network(id).await?.ok_or(ApiError::NotFound)?;
    Ok(HttpResponse::Ok().json(NetworkResponse::from_model(network)))
}

#[derive(Debug, Deserialize)]
struct UpdateNetworkRequest {
    dns_servers: Vec<String>,
    #[serde(default = "default_keepalive")]
    persistent_keepalive: i32,
}

async fn update_network(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateNetworkRequest>,
) -> Result<HttpResponse, ApiError> {
    validate_dns_servers(&body.dns_servers)?;
    let id = path.into_inner();
    let network = store
        .update_network_settings(id, &body.dns_servers, body.persistent_keepalive)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(HttpResponse::Ok().json(NetworkResponse::from_model(network)))
}

async fn delete_network(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    store.delete_network(id).await?;
    Ok(HttpResponse::NoContent().finish())
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/networks")
            .route("", web::get().to(list_networks))
            .route("", web::post().to(create_network))
            .route("/{id}", web::get().to(get_network))
            .route("/{id}", web::patch().to(update_network))
            .route("/{id}", web::delete().to(delete_network))
            .route("/{id}/servers", web::get().to(super::servers::list_servers))
            .route("/{id}/clients", web::get().to(super::clients::list_clients)),
    );
}
