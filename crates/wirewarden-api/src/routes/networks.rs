use actix_web::{web, HttpResponse};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::vpn::VpnStore;
use crate::error::ApiError;
use crate::extract::AuthUser;

#[derive(Debug, Deserialize)]
struct CreateNetworkRequest {
    name: String,
    cidr: String,
    dns_servers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NetworkResponse {
    id: Uuid,
    name: String,
    cidr: String,
    dns_servers: Vec<String>,
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

    let prefix = cidr.prefix() as i32;
    let network = store
        .create_network(&body.name, cidr, prefix, None, &body.dns_servers)
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
            .route("/{id}", web::delete().to(delete_network)),
    );
}
