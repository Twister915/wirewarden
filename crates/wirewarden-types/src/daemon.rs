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

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub server: DaemonServerInfo,
    pub network: DaemonNetworkInfo,
    pub peers: Vec<DaemonPeer>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DaemonServerInfo {
    pub id: Uuid,
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    pub listen_port: i32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DaemonNetworkInfo {
    pub id: Uuid,
    pub name: String,
    pub cidr: String,
    pub persistent_keepalive: i32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DaemonPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
}
