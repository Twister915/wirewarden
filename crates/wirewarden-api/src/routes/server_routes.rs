use actix_web::{web, HttpResponse};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::vpn::VpnStore;
use crate::error::ApiError;
use crate::extract::AuthUser;

#[derive(Debug, Deserialize)]
struct CreateRouteRequest {
    route_cidr: String,
}

#[derive(Debug, Serialize)]
struct RouteResponse {
    id: Uuid,
    server_id: Uuid,
    route_cidr: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

async fn list_routes(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let server_id = path.into_inner();
    let routes = store.list_routes_by_server(server_id).await?;
    let resp: Vec<_> = routes
        .into_iter()
        .map(|r| RouteResponse {
            id: r.id,
            server_id: r.server_id,
            route_cidr: r.route_cidr.to_string(),
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();
    Ok(HttpResponse::Ok().json(resp))
}

async fn add_route(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
    body: web::Json<CreateRouteRequest>,
) -> Result<HttpResponse, ApiError> {
    let server_id = path.into_inner();
    let cidr: IpNetwork = body
        .route_cidr
        .parse()
        .map_err(|_| ApiError::Validation("invalid CIDR".into()))?;

    let route = store.add_route(server_id, cidr).await?;
    let resp = RouteResponse {
        id: route.id,
        server_id: route.server_id,
        route_cidr: route.route_cidr.to_string(),
        created_at: route.created_at,
        updated_at: route.updated_at,
    };
    Ok(HttpResponse::Created().json(resp))
}

async fn delete_route(
    _auth: AuthUser,
    store: web::Data<VpnStore>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    store.delete_route(id).await?;
    Ok(HttpResponse::NoContent().finish())
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/api/servers/{id}/routes")
            .route(web::get().to(list_routes))
            .route(web::post().to(add_route)),
    )
    .service(
        web::resource("/api/routes/{id}")
            .route(web::delete().to(delete_route)),
    );
}
