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

use std::net::IpAddr;

use thiserror::Error;
use wirewarden_types::daemon::DaemonConfig;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("not supported on this platform")]
    Unsupported,

    #[error("wireguard interface error: {0}")]
    Interface(String),

    #[error("failed to decode base64 key: {0}")]
    KeyDecode(#[from] base64::DecodeError),

    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("IP address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("CIDR parse error: {0}")]
    CidrParse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub trait Platform {
    fn ensure_interface(name: &str) -> impl Future<Output = Result<(), PlatformError>> + Send;
    fn remove_interface(name: &str) -> impl Future<Output = Result<(), PlatformError>> + Send;
    fn apply_config(
        name: &str,
        config: &DaemonConfig,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;
    fn interface_exists(name: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send;
}

use std::future::Future;

#[cfg(target_os = "linux")]
pub type CurrentPlatform = linux::LinuxPlatform;

#[cfg(not(target_os = "linux"))]
pub type CurrentPlatform = StubPlatform;

// -- Helper utilities --

pub fn decode_key(b64: &str) -> Result<[u8; 32], PlatformError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| PlatformError::InvalidKeyLength(len))
}

pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), PlatformError> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| PlatformError::CidrParse(s.to_string()))?;
    let addr: IpAddr = addr_str.parse()?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| PlatformError::CidrParse(s.to_string()))?;
    Ok((addr, prefix))
}

// -- Stub platform for non-Linux --

pub struct StubPlatform;

impl Platform for StubPlatform {
    async fn ensure_interface(_name: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    async fn remove_interface(_name: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    async fn apply_config(_name: &str, _config: &DaemonConfig) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    async fn interface_exists(_name: &str) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

// -- Linux implementation --

#[cfg(target_os = "linux")]
pub mod linux {
    use std::net::{IpAddr, SocketAddr};

    use futures::TryStreamExt;
    use tracing::{debug, info};
    use wireguard_uapi::{RouteSocket, WgSocket, set};

    use wirewarden_types::daemon::DaemonConfig;

    use super::{Platform, PlatformError, decode_key, parse_cidr};

    pub struct LinuxPlatform;

    impl Platform for LinuxPlatform {
        async fn ensure_interface(name: &str) -> Result<(), PlatformError> {
            let mut route = RouteSocket::connect()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
            let existing = route.list_device_names()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;

            if existing.iter().any(|n| n == name) {
                debug!(interface = name, "interface already exists");
                return Ok(());
            }

            info!(interface = name, "creating wireguard interface");
            route.add_device(name)
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
            Ok(())
        }

        async fn remove_interface(name: &str) -> Result<(), PlatformError> {
            let mut route = RouteSocket::connect()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
            let existing = route.list_device_names()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;

            if existing.iter().any(|n| n == name) {
                info!(interface = name, "removing interface");
                route.del_device(name)
                    .map_err(|e| PlatformError::Interface(e.to_string()))?;
            }
            Ok(())
        }

        async fn apply_config(name: &str, config: &DaemonConfig) -> Result<(), PlatformError> {
            Self::ensure_interface(name).await?;
            apply_device_config(name, config)?;
            assign_address(name, &config.server.address).await?;
            set_link_up(name).await?;
            info!(interface = name, server = %config.server.name, "applied configuration");
            Ok(())
        }

        async fn interface_exists(name: &str) -> Result<bool, PlatformError> {
            let mut route = RouteSocket::connect()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
            let existing = route.list_device_names()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
            Ok(existing.iter().any(|n| n == name))
        }
    }

    fn apply_device_config(name: &str, config: &DaemonConfig) -> Result<(), PlatformError> {
        let private_key = decode_key(&config.server.private_key)?;
        let listen_port = config.server.listen_port as u16;

        let peer_data: Vec<PeerOwned> = config
            .peers
            .iter()
            .map(|p| {
                let pub_key = decode_key(&p.public_key)?;
                let endpoint: Option<SocketAddr> = p
                    .endpoint
                    .as_deref()
                    .and_then(|ep| ep.parse().ok());
                let allowed_ips: Vec<(IpAddr, u8)> = p
                    .allowed_ips
                    .iter()
                    .map(|ip| parse_cidr(ip))
                    .collect::<Result<_, _>>()?;
                let persistent_keepalive = config.network.persistent_keepalive;
                Ok(PeerOwned { pub_key, endpoint, allowed_ips, persistent_keepalive })
            })
            .collect::<Result<_, PlatformError>>()?;

        let peers: Vec<set::Peer<'_>> = peer_data
            .iter()
            .map(|p| {
                let mut peer = set::Peer::from_public_key(&p.pub_key)
                    .flags(vec![set::WgPeerF::ReplaceAllowedIps]);

                if let Some(ref ep) = p.endpoint {
                    peer = peer.endpoint(ep);
                }

                let allowed: Vec<set::AllowedIp<'_>> = p
                    .allowed_ips
                    .iter()
                    .map(|(addr, cidr)| {
                        let mut aip = set::AllowedIp::from_ipaddr(addr);
                        aip.cidr_mask = Some(*cidr);
                        aip
                    })
                    .collect();

                if p.persistent_keepalive > 0 {
                    peer = peer.persistent_keepalive_interval(p.persistent_keepalive as u16);
                }

                peer.allowed_ips(allowed)
            })
            .collect();

        let dev = set::Device::from_ifname(name)
            .private_key(&private_key)
            .listen_port(listen_port)
            .flags(vec![set::WgDeviceF::ReplacePeers])
            .peers(peers);

        let mut wg = WgSocket::connect()
            .map_err(|e| PlatformError::Interface(e.to_string()))?;
        wg.set_device(dev)
            .map_err(|e| PlatformError::Interface(e.to_string()))?;

        debug!(
            interface = name,
            listen_port,
            peer_count = config.peers.len(),
            "applied wireguard device config"
        );
        Ok(())
    }

    struct PeerOwned {
        pub_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<(IpAddr, u8)>,
        persistent_keepalive: i32,
    }

    /// Resolve interface name to its index via rtnetlink.
    async fn get_link_index(
        handle: &rtnetlink::Handle,
        name: &str,
    ) -> Result<u32, PlatformError> {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        let link = links
            .try_next()
            .await
            .map_err(|e| PlatformError::Interface(e.to_string()))?
            .ok_or_else(|| PlatformError::Interface(format!("interface {name} not found")))?;
        Ok(link.header.index)
    }

    async fn assign_address(name: &str, address: &str) -> Result<(), PlatformError> {
        let (addr, prefix) = if address.contains('/') {
            parse_cidr(address)?
        } else {
            let addr: IpAddr = address.parse()?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            (addr, prefix)
        };

        let (conn, handle, _) = rtnetlink::new_connection()
            .map_err(|e| PlatformError::Io(e))?;
        tokio::spawn(conn);

        let index = get_link_index(&handle, name).await?;

        // Flush existing addresses
        let existing: Vec<_> = handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute()
            .try_collect()
            .await
            .map_err(|e| PlatformError::Interface(e.to_string()))?;

        for addr_msg in existing {
            handle
                .address()
                .del(addr_msg)
                .execute()
                .await
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
        }
        debug!(interface = name, "flushed existing addresses");

        // Add new address
        handle
            .address()
            .add(index, addr, prefix)
            .execute()
            .await
            .map_err(|e| PlatformError::Interface(e.to_string()))?;

        info!(interface = name, %addr, prefix, "assigned address via netlink");
        Ok(())
    }

    async fn set_link_up(name: &str) -> Result<(), PlatformError> {
        let (conn, handle, _) = rtnetlink::new_connection()
            .map_err(|e| PlatformError::Io(e))?;
        tokio::spawn(conn);

        let index = get_link_index(&handle, name).await?;

        let msg = rtnetlink::LinkUnspec::new_with_index(index)
            .up()
            .build();
        handle
            .link()
            .set(msg)
            .execute()
            .await
            .map_err(|e| PlatformError::Interface(e.to_string()))?;

        info!(interface = name, "set link up via netlink");
        Ok(())
    }
}
