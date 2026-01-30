//! wirewarden-types: Shared API type definitions for the wirewarden ecosystem.
//!
//! This crate contains the data models, request/response types, and error
//! definitions shared between the API server, daemon, and frontend.

#![warn(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A WireGuard server (peer that acts as a relay/gateway).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Unique identifier.
    pub id: Uuid,
    /// Human-readable name for this server.
    pub name: String,
    /// WireGuard public key.
    pub public_key: String,
    /// Endpoint address (host:port).
    pub endpoint: String,
    /// Allowed IP ranges this server routes.
    pub allowed_ips: Vec<String>,
    /// When this server was registered.
    pub created_at: DateTime<Utc>,
    /// Last time the daemon checked in.
    pub last_seen: Option<DateTime<Utc>>,
}

/// A WireGuard client (peer that connects to a server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    /// Unique identifier.
    pub id: Uuid,
    /// Human-readable name (e.g. "Dad's laptop").
    pub name: String,
    /// WireGuard public key.
    pub public_key: String,
    /// Assigned IP address within the VPN.
    pub assigned_ip: String,
    /// Which server this client connects through.
    pub server_id: Uuid,
    /// When this client was created.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_serializes() {
        let server = Server {
            id: Uuid::new_v4(),
            name: "home-pi".to_string(),
            public_key: "test-key".to_string(),
            endpoint: "vpn.example.com:51820".to_string(),
            allowed_ips: vec!["10.0.0.0/24".to_string()],
            created_at: Utc::now(),
            last_seen: None,
        };
        let json = serde_json::to_string(&server).unwrap();
        assert!(json.contains("home-pi"));
    }
}
