use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub server: DaemonServerInfo,
    pub network: DaemonNetworkInfo,
    pub peers: Vec<DaemonPeer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonServerInfo {
    pub id: Uuid,
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    pub listen_port: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonNetworkInfo {
    pub id: Uuid,
    pub name: String,
    pub cidr: String,
    pub persistent_keepalive: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
}
