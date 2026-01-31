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

use std::collections::HashMap;
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

/// Interface name prefix for wirewarden-managed WireGuard interfaces.
pub const IFACE_PREFIX: &str = "wwg";

pub trait Platform {
    fn ensure_interface(name: &str) -> impl Future<Output = Result<(), PlatformError>> + Send;
    fn remove_interface(name: &str) -> impl Future<Output = Result<(), PlatformError>> + Send;
    fn apply_config(
        name: &str,
        config: &DaemonConfig,
        prev: Option<&DaemonConfig>,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;
    fn interface_exists(name: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send;

    /// List all wirewarden-managed interfaces (`wwg*`) and their private keys.
    ///
    /// Returns a map of interface name to base64-encoded private key.
    fn list_managed_interfaces()
    -> impl Future<Output = Result<HashMap<String, String>, PlatformError>> + Send;
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

    async fn apply_config(
        _name: &str,
        _config: &DaemonConfig,
        _prev: Option<&DaemonConfig>,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    async fn interface_exists(_name: &str) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    async fn list_managed_interfaces() -> Result<HashMap<String, String>, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

// -- Linux implementation --

#[cfg(target_os = "linux")]
pub mod linux {
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};

    use futures::TryStreamExt;
    use tracing::{debug, info};
    use wireguard_uapi::{DeviceInterface, RouteSocket, WgSocket, set};

    use wirewarden_types::daemon::{DaemonConfig, DaemonPeer};

    use super::{Platform, PlatformError, decode_key, parse_cidr};

    pub struct LinuxPlatform;

    impl Platform for LinuxPlatform {
        async fn ensure_interface(name: &str) -> Result<(), PlatformError> {
            let mut route =
                RouteSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
            let existing = route
                .list_device_names()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;

            if existing.iter().any(|n| n == name) {
                debug!(interface = name, "interface already exists");
                return Ok(());
            }

            info!(interface = name, "creating wireguard interface");
            route
                .add_device(name)
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
            Ok(())
        }

        async fn remove_interface(name: &str) -> Result<(), PlatformError> {
            let mut route =
                RouteSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
            let existing = route
                .list_device_names()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;

            if existing.iter().any(|n| n == name) {
                info!(interface = name, "removing interface");
                route
                    .del_device(name)
                    .map_err(|e| PlatformError::Interface(e.to_string()))?;
            }
            Ok(())
        }

        async fn apply_config(
            name: &str,
            config: &DaemonConfig,
            prev: Option<&DaemonConfig>,
        ) -> Result<(), PlatformError> {
            let created = !Self::interface_exists(name).await?;
            if created {
                Self::ensure_interface(name).await?;
            }

            match prev {
                Some(prev) if !created => {
                    apply_config_diff(name, prev, config)?;

                    if prev.server.address != config.server.address {
                        assign_address(name, &config.server.address).await?;
                    }

                    info!(
                        interface = name,
                        server = %config.server.name,
                        "applied differential configuration"
                    );
                }
                _ => {
                    apply_device_config(name, config)?;
                    assign_address(name, &config.server.address).await?;
                    set_link_up(name).await?;
                    info!(
                        interface = name,
                        server = %config.server.name,
                        "applied full configuration"
                    );
                }
            }

            Ok(())
        }

        async fn interface_exists(name: &str) -> Result<bool, PlatformError> {
            let mut route =
                RouteSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
            let existing = route
                .list_device_names()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;
            Ok(existing.iter().any(|n| n == name))
        }

        async fn list_managed_interfaces() -> Result<HashMap<String, String>, PlatformError> {
            use base64::Engine;

            let mut route =
                RouteSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
            let all_names = route
                .list_device_names()
                .map_err(|e| PlatformError::Interface(e.to_string()))?;

            let managed: Vec<&str> = all_names
                .iter()
                .filter(|n| n.starts_with(super::IFACE_PREFIX))
                .map(|n| n.as_str())
                .collect();

            let mut result = HashMap::with_capacity(managed.len());

            let mut wg =
                WgSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;

            for name in managed {
                let device = wg
                    .get_device(DeviceInterface::from_name(name))
                    .map_err(|e| PlatformError::Interface(e.to_string()))?;

                if let Some(key) = device.private_key {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
                    debug!(interface = name, "discovered managed interface");
                    result.insert(name.to_owned(), encoded);
                }
            }

            Ok(result)
        }
    }

    fn apply_device_config(name: &str, config: &DaemonConfig) -> Result<(), PlatformError> {
        let private_key = decode_key(&config.server.private_key)?;
        let listen_port = config.server.listen_port as u16;

        let peer_data: Vec<PeerOwned> = config
            .peers
            .iter()
            .map(|p| build_peer_owned(p, config.network.persistent_keepalive))
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

        let mut wg = WgSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
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

    fn apply_config_diff(
        name: &str,
        prev: &DaemonConfig,
        next: &DaemonConfig,
    ) -> Result<(), PlatformError> {
        let key_changed = prev.server.private_key != next.server.private_key;
        let port_changed = prev.server.listen_port != next.server.listen_port;

        if key_changed || port_changed {
            set_device_key_port(name, next)?;
        }

        let prev_peers: HashMap<&str, &DaemonPeer> = prev
            .peers
            .iter()
            .map(|p| (p.public_key.as_str(), p))
            .collect();
        let next_peers: HashMap<&str, &DaemonPeer> = next
            .peers
            .iter()
            .map(|p| (p.public_key.as_str(), p))
            .collect();

        let added: Vec<&DaemonPeer> = next_peers
            .iter()
            .filter(|(k, _)| !prev_peers.contains_key(*k))
            .map(|(_, p)| *p)
            .collect();

        let removed: Vec<&str> = prev_peers
            .keys()
            .filter(|k| !next_peers.contains_key(*k))
            .copied()
            .collect();

        let updated: Vec<&DaemonPeer> = next_peers
            .iter()
            .filter(|(k, p)| prev_peers.get(*k).is_some_and(|old| old != *p))
            .map(|(_, p)| *p)
            .collect();

        if !added.is_empty() {
            debug!(interface = name, count = added.len(), "adding peers");
            add_peers(name, &added, next.network.persistent_keepalive)?;
        }

        if !removed.is_empty() {
            debug!(interface = name, count = removed.len(), "removing peers");
            remove_peers(name, &removed)?;
        }

        if !updated.is_empty() {
            debug!(interface = name, count = updated.len(), "updating peers");
            update_peers(name, &updated, next.network.persistent_keepalive)?;
        }

        if added.is_empty()
            && removed.is_empty()
            && updated.is_empty()
            && !key_changed
            && !port_changed
        {
            debug!(interface = name, "no device-level changes needed");
        }

        Ok(())
    }

    fn set_device_key_port(name: &str, config: &DaemonConfig) -> Result<(), PlatformError> {
        let private_key = decode_key(&config.server.private_key)?;
        let listen_port = config.server.listen_port as u16;

        let dev = set::Device::from_ifname(name)
            .private_key(&private_key)
            .listen_port(listen_port);

        let mut wg = WgSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
        wg.set_device(dev)
            .map_err(|e| PlatformError::Interface(e.to_string()))?;

        debug!(interface = name, listen_port, "updated device key/port");
        Ok(())
    }

    fn build_peer_owned(
        peer: &DaemonPeer,
        persistent_keepalive: i32,
    ) -> Result<PeerOwned, PlatformError> {
        let pub_key = decode_key(&peer.public_key)?;
        let endpoint: Option<SocketAddr> = peer.endpoint.as_deref().and_then(|ep| ep.parse().ok());
        let preshared_key = match peer.preshared_key.as_deref() {
            Some(psk) => Some(decode_key(psk)?),
            None => None,
        };
        let allowed_ips: Vec<(IpAddr, u8)> = peer
            .allowed_ips
            .iter()
            .map(|ip| parse_cidr(ip))
            .collect::<Result<_, _>>()?;
        Ok(PeerOwned {
            pub_key,
            endpoint,
            allowed_ips,
            persistent_keepalive,
            preshared_key,
        })
    }

    fn build_set_peer<'a>(p: &'a PeerOwned, flags: Vec<set::WgPeerF>) -> set::Peer<'a> {
        let mut peer = set::Peer::from_public_key(&p.pub_key).flags(flags);

        if let Some(ref ep) = p.endpoint {
            peer = peer.endpoint(ep);
        }
        if let Some(ref psk) = p.preshared_key {
            peer = peer.preshared_key(psk);
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
    }

    fn add_peers(
        name: &str,
        peers: &[&DaemonPeer],
        persistent_keepalive: i32,
    ) -> Result<(), PlatformError> {
        let owned: Vec<PeerOwned> = peers
            .iter()
            .map(|p| build_peer_owned(p, persistent_keepalive))
            .collect::<Result<_, _>>()?;

        let set_peers: Vec<set::Peer<'_>> = owned
            .iter()
            .map(|p| build_set_peer(p, vec![set::WgPeerF::ReplaceAllowedIps]))
            .collect();

        let dev = set::Device::from_ifname(name).peers(set_peers);

        let mut wg = WgSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
        wg.set_device(dev)
            .map_err(|e| PlatformError::Interface(e.to_string()))?;
        Ok(())
    }

    fn remove_peers(name: &str, pub_keys: &[&str]) -> Result<(), PlatformError> {
        let keys: Vec<[u8; 32]> = pub_keys
            .iter()
            .map(|k| decode_key(k))
            .collect::<Result<_, _>>()?;

        let set_peers: Vec<set::Peer<'_>> = keys
            .iter()
            .map(|k| set::Peer::from_public_key(k).flags(vec![set::WgPeerF::RemoveMe]))
            .collect();

        let dev = set::Device::from_ifname(name).peers(set_peers);

        let mut wg = WgSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
        wg.set_device(dev)
            .map_err(|e| PlatformError::Interface(e.to_string()))?;
        Ok(())
    }

    fn update_peers(
        name: &str,
        peers: &[&DaemonPeer],
        persistent_keepalive: i32,
    ) -> Result<(), PlatformError> {
        let owned: Vec<PeerOwned> = peers
            .iter()
            .map(|p| build_peer_owned(p, persistent_keepalive))
            .collect::<Result<_, _>>()?;

        let set_peers: Vec<set::Peer<'_>> = owned
            .iter()
            .map(|p| {
                build_set_peer(
                    p,
                    vec![set::WgPeerF::UpdateOnly, set::WgPeerF::ReplaceAllowedIps],
                )
            })
            .collect();

        let dev = set::Device::from_ifname(name).peers(set_peers);

        let mut wg = WgSocket::connect().map_err(|e| PlatformError::Interface(e.to_string()))?;
        wg.set_device(dev)
            .map_err(|e| PlatformError::Interface(e.to_string()))?;
        Ok(())
    }

    struct PeerOwned {
        pub_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<(IpAddr, u8)>,
        persistent_keepalive: i32,
        preshared_key: Option<[u8; 32]>,
    }

    /// Resolve interface name to its index via rtnetlink.
    async fn get_link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, PlatformError> {
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

        let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| PlatformError::Io(e))?;
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
        let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| PlatformError::Io(e))?;
        tokio::spawn(conn);

        let index = get_link_index(&handle, name).await?;

        let msg = rtnetlink::LinkUnspec::new_with_index(index).up().build();
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
