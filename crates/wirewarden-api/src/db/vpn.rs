use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ipnetwork::{IpNetwork, Ipv4Network};
use sqlx::PgPool;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Model types
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub struct Network {
    pub id: Uuid,
    pub name: String,
    pub cidr_ip: IpNetwork,
    pub cidr_prefix: i32,
    pub owner_id: Option<Uuid>,
    pub dns_servers: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct WgKey {
    pub id: Uuid,
    pub private_key: String,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct WgKeyRow {
    id: Uuid,
    private_key_enc: Vec<u8>,
    private_key_nonce: Vec<u8>,
    public_key: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct WgServer {
    pub id: Uuid,
    pub network_id: Uuid,
    pub name: String,
    pub key_id: Uuid,
    pub api_token: String,
    pub address_offset: i32,
    pub forwards_internet_traffic: bool,
    pub endpoint_host: Option<String>,
    pub endpoint_port: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct WgClient {
    pub id: Uuid,
    pub network_id: Uuid,
    pub name: String,
    pub key_id: Uuid,
    pub address_offset: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct WgServerRoute {
    pub id: Uuid,
    pub server_id: Uuid,
    pub route_cidr: IpNetwork,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Network snapshot (for config generation)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct NetworkSnapshot {
    pub network: Network,
    pub servers: Vec<WgServer>,
    pub keys: HashMap<Uuid, WgKey>,
    pub server_routes: HashMap<Uuid, Vec<WgServerRoute>>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VpnStoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("network name already taken")]
    DuplicateNetworkName,

    #[error("name already taken in this network")]
    DuplicateName,

    #[error("address offset {offset} conflicts with an existing server or client")]
    AddressOffsetConflict { offset: i32 },

    #[error("offset {offset} out of range (max {max})")]
    OffsetOutOfRange { offset: i32, max: i32 },

    #[error("network not found")]
    NetworkNotFound,

    #[error("key not found")]
    KeyNotFound,

    #[error("server not found")]
    ServerNotFound,

    #[error("no available address offsets in this network")]
    NetworkFull,

    #[error("key encryption/decryption failed")]
    KeyEncryption,
}

type Result<T> = std::result::Result<T, VpnStoreError>;

// ---------------------------------------------------------------------------
// Batch lookup helper
// ---------------------------------------------------------------------------

macro_rules! batch_by_ids {
    ($pool:expr, $table:expr, $ty:ty, $ids:expr) => {
        sqlx::query_as::<_, $ty>(
            concat!("SELECT * FROM ", $table, " WHERE id = ANY($1)"),
        )
        .bind($ids)
        .fetch_all($pool)
        .await
    };
}

// ---------------------------------------------------------------------------
// VpnStore
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VpnStore {
    pool: PgPool,
    encryption_key: [u8; 32],
}

impl VpnStore {
    pub fn new(pool: PgPool, encryption_key: [u8; 32]) -> Self {
        Self { pool, encryption_key }
    }

    // -- Encryption helpers --------------------------------------------------

    fn encrypt_private_key(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| VpnStoreError::KeyEncryption)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| VpnStoreError::KeyEncryption)?;
        Ok((ciphertext, nonce.to_vec()))
    }

    fn decrypt_private_key(&self, ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| VpnStoreError::KeyEncryption)?;
        let nonce =
            Nonce::from_exact_iter(nonce_bytes.iter().copied()).ok_or(VpnStoreError::KeyEncryption)?;
        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| VpnStoreError::KeyEncryption)
    }

    fn decrypt_key_row(&self, row: WgKeyRow) -> Result<WgKey> {
        let plaintext = self.decrypt_private_key(&row.private_key_enc, &row.private_key_nonce)?;
        Ok(WgKey {
            id: row.id,
            private_key: BASE64.encode(&plaintext),
            public_key: row.public_key,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    // -- Network CRUD --------------------------------------------------------

    #[tracing::instrument(skip(self))]
    pub async fn create_network(
        &self,
        name: &str,
        cidr_ip: IpNetwork,
        cidr_prefix: i32,
        owner_id: Option<Uuid>,
        dns_servers: &[String],
    ) -> Result<Network> {
        sqlx::query_as::<_, Network>(
            "INSERT INTO networks (name, cidr_ip, cidr_prefix, owner_id, dns_servers)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *",
        )
        .bind(name)
        .bind(cidr_ip)
        .bind(cidr_prefix)
        .bind(owner_id)
        .bind(dns_servers)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.constraint() == Some("networks_name_key") => {
                VpnStoreError::DuplicateNetworkName
            }
            _ => VpnStoreError::Database(e),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_network(&self, id: Uuid) -> Result<Option<Network>> {
        sqlx::query_as::<_, Network>("SELECT * FROM networks WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_networks(&self) -> Result<Vec<Network>> {
        sqlx::query_as::<_, Network>("SELECT * FROM networks ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn update_network_dns(
        &self,
        id: Uuid,
        dns_servers: &[String],
    ) -> Result<Option<Network>> {
        sqlx::query_as::<_, Network>(
            "UPDATE networks SET dns_servers = $2, updated_at = now() WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(dns_servers)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_network(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM networks WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- WgKey CRUD ----------------------------------------------------------

    #[tracing::instrument(skip(self))]
    pub async fn create_key(&self) -> Result<WgKey> {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);

        let private_bytes = secret.to_bytes();
        let (enc, nonce) = self.encrypt_private_key(&private_bytes)?;
        let public_b64 = BASE64.encode(public.as_bytes());

        let row = sqlx::query_as::<_, WgKeyRow>(
            "INSERT INTO wg_keys (private_key_enc, private_key_nonce, public_key)
             VALUES ($1, $2, $3)
             RETURNING *",
        )
        .bind(&enc)
        .bind(&nonce)
        .bind(&public_b64)
        .fetch_one(&self.pool)
        .await?;

        self.decrypt_key_row(row)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_key(&self, id: Uuid) -> Result<WgKey> {
        let row = sqlx::query_as::<_, WgKeyRow>("SELECT * FROM wg_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(VpnStoreError::KeyNotFound)?;

        self.decrypt_key_row(row)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_keys_batch(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, WgKey>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<WgKeyRow> = batch_by_ids!(&self.pool, "wg_keys", WgKeyRow, ids)?;
        let mut map = HashMap::with_capacity(rows.len());
        for row in rows {
            let id = row.id;
            let key = self.decrypt_key_row(row)?;
            map.insert(id, key);
        }
        Ok(map)
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_key(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM wg_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- Offset allocation ---------------------------------------------------

    async fn next_offset(&self, network_id: Uuid) -> Result<i32> {
        let network = self
            .get_network(network_id)
            .await?
            .ok_or(VpnStoreError::NetworkNotFound)?;

        let max = (1i64 << (32 - network.cidr_prefix)) - 1;

        let used: Vec<(i32,)> = sqlx::query_as(
            "SELECT address_offset FROM wg_servers WHERE network_id = $1
             UNION
             SELECT address_offset FROM wg_clients WHERE network_id = $1
             ORDER BY address_offset",
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await?;

        let mut candidate = 1i32;
        for (offset,) in &used {
            if *offset != candidate {
                break;
            }
            candidate += 1;
        }

        if candidate as i64 >= max {
            return Err(VpnStoreError::NetworkFull);
        }

        Ok(candidate)
    }

    // -- WgServer CRUD -------------------------------------------------------

    #[tracing::instrument(skip(self))]
    pub async fn create_server(
        &self,
        network_id: Uuid,
        name: &str,
        key_id: Uuid,
        forwards_internet_traffic: bool,
        endpoint_host: Option<&str>,
        endpoint_port: i32,
    ) -> Result<WgServer> {
        let address_offset = self.next_offset(network_id).await?;

        let api_token = Uuid::new_v4().to_string();

        sqlx::query_as::<_, WgServer>(
            "INSERT INTO wg_servers (network_id, name, key_id, api_token, address_offset, forwards_internet_traffic, endpoint_host, endpoint_port)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING *",
        )
        .bind(network_id)
        .bind(name)
        .bind(key_id)
        .bind(&api_token)
        .bind(address_offset)
        .bind(forwards_internet_traffic)
        .bind(endpoint_host)
        .bind(endpoint_port)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) => {
                match db_err.constraint() {
                    Some("wg_servers_network_id_name_key") => VpnStoreError::DuplicateName,
                    Some("wg_servers_network_id_address_offset_key") => {
                        VpnStoreError::AddressOffsetConflict { offset: address_offset }
                    }
                    _ => VpnStoreError::Database(e),
                }
            }
            _ => VpnStoreError::Database(e),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_server(&self, id: Uuid) -> Result<Option<WgServer>> {
        sqlx::query_as::<_, WgServer>("SELECT * FROM wg_servers WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self, api_token))]
    pub async fn get_server_by_token(&self, api_token: &str) -> Result<Option<WgServer>> {
        sqlx::query_as::<_, WgServer>("SELECT * FROM wg_servers WHERE api_token = $1")
            .bind(api_token)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_servers_by_network(&self, network_id: Uuid) -> Result<Vec<WgServer>> {
        sqlx::query_as::<_, WgServer>(
            "SELECT * FROM wg_servers WHERE network_id = $1 ORDER BY created_at",
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_server(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM wg_servers WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- WgClient CRUD -------------------------------------------------------

    #[tracing::instrument(skip(self))]
    pub async fn create_client(
        &self,
        network_id: Uuid,
        name: &str,
        key_id: Uuid,
    ) -> Result<WgClient> {
        let address_offset = self.next_offset(network_id).await?;

        sqlx::query_as::<_, WgClient>(
            "INSERT INTO wg_clients (network_id, name, key_id, address_offset)
             VALUES ($1, $2, $3, $4)
             RETURNING *",
        )
        .bind(network_id)
        .bind(name)
        .bind(key_id)
        .bind(address_offset)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) => {
                match db_err.constraint() {
                    Some("wg_clients_network_id_name_key") => VpnStoreError::DuplicateName,
                    Some("wg_clients_network_id_address_offset_key") => {
                        VpnStoreError::AddressOffsetConflict { offset: address_offset }
                    }
                    _ => VpnStoreError::Database(e),
                }
            }
            _ => VpnStoreError::Database(e),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_client(&self, id: Uuid) -> Result<Option<WgClient>> {
        sqlx::query_as::<_, WgClient>("SELECT * FROM wg_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_clients_by_network(&self, network_id: Uuid) -> Result<Vec<WgClient>> {
        sqlx::query_as::<_, WgClient>(
            "SELECT * FROM wg_clients WHERE network_id = $1 ORDER BY created_at",
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_client(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM wg_clients WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- WgServerRoute CRUD --------------------------------------------------

    #[tracing::instrument(skip(self))]
    pub async fn add_route(&self, server_id: Uuid, route_cidr: IpNetwork) -> Result<WgServerRoute> {
        sqlx::query_as::<_, WgServerRoute>(
            "INSERT INTO wg_server_routes (server_id, route_cidr)
             VALUES ($1, $2)
             RETURNING *",
        )
        .bind(server_id)
        .bind(route_cidr)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_routes_by_server(&self, server_id: Uuid) -> Result<Vec<WgServerRoute>> {
        sqlx::query_as::<_, WgServerRoute>(
            "SELECT * FROM wg_server_routes WHERE server_id = $1 ORDER BY route_cidr",
        )
        .bind(server_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_route(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM wg_server_routes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- Network snapshot ----------------------------------------------------

    #[tracing::instrument(skip(self))]
    pub async fn load_network_snapshot(&self, network_id: Uuid) -> Result<NetworkSnapshot> {
        let network = self
            .get_network(network_id)
            .await?
            .ok_or(VpnStoreError::NetworkNotFound)?;

        let servers = self.list_servers_by_network(network_id).await?;

        let mut keys = HashMap::new();
        let mut server_routes = HashMap::new();

        for server in &servers {
            if !keys.contains_key(&server.key_id) {
                let key = self.get_key(server.key_id).await?;
                keys.insert(key.id, key);
            }
            let routes = self.list_routes_by_server(server.id).await?;
            server_routes.insert(server.id, routes);
        }

        Ok(NetworkSnapshot {
            network,
            servers,
            keys,
            server_routes,
        })
    }
}

// ---------------------------------------------------------------------------
// CIDR math helpers
// ---------------------------------------------------------------------------

fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

fn network_contains(net: Ipv4Network, other: Ipv4Network) -> bool {
    net.prefix() <= other.prefix() && net.contains(other.ip())
}

/// Subtract `exclude` from `base`, returning the remaining CIDRs.
fn cidr_subtract(base: Ipv4Network, exclude: Ipv4Network) -> Vec<Ipv4Network> {
    if !network_contains(base, exclude) && !network_contains(exclude, base) {
        return vec![base];
    }
    if network_contains(exclude, base) {
        return vec![];
    }
    if base.prefix() >= 32 {
        return vec![];
    }

    let new_prefix = base.prefix() + 1;
    let base_ip = ip_to_u32(base.network());
    let half_size = 1u32 << (32 - new_prefix);

    let left = Ipv4Network::new(u32_to_ip(base_ip), new_prefix).unwrap();
    let right = Ipv4Network::new(u32_to_ip(base_ip + half_size), new_prefix).unwrap();

    let mut result = Vec::new();
    for half in [left, right] {
        if network_contains(exclude, half) {
            // entirely excluded
        } else if !network_contains(half, exclude) && !network_contains(exclude, half) {
            result.push(half);
        } else {
            result.extend(cidr_subtract(half, exclude));
        }
    }
    result
}

/// Subtract multiple excludes from base.
fn cidr_subtract_many(base: Ipv4Network, excludes: &[Ipv4Network]) -> Vec<Ipv4Network> {
    let mut remaining = vec![base];
    for &exclude in excludes {
        let mut next = Vec::new();
        for r in remaining {
            next.extend(cidr_subtract(r, exclude));
        }
        remaining = next;
    }
    remaining
}

const RFC1918: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

fn rfc1918_networks() -> Vec<Ipv4Network> {
    RFC1918
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
}

/// Compute the IP address for a given network + offset.
pub fn compute_address(network: &Network, offset: i32) -> Ipv4Addr {
    let base = match network.cidr_ip {
        IpNetwork::V4(v4) => ip_to_u32(v4.ip()),
        IpNetwork::V6(_) => panic!("IPv6 not supported"),
    };
    u32_to_ip(base + offset as u32)
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

impl WgClient {
    pub fn wg_quick_config(
        &self,
        key: &WgKey,
        snapshot: &NetworkSnapshot,
        forward_internet: bool,
    ) -> String {
        let client_ip = compute_address(&snapshot.network, self.address_offset);
        let prefix = snapshot.network.cidr_prefix;

        let mut config = String::new();
        writeln!(config, "# {}", self.name).unwrap();
        writeln!(config, "[Interface]").unwrap();
        writeln!(config, "# PublicKey = {}", key.public_key).unwrap();
        writeln!(config, "PrivateKey = {}", key.private_key).unwrap();
        writeln!(config, "Address = {client_ip}/{prefix}").unwrap();

        if forward_internet && !snapshot.network.dns_servers.is_empty() {
            writeln!(config, "DNS = {}", snapshot.network.dns_servers.join(", ")).unwrap();
        }

        let vpn_cidr: Ipv4Network = match snapshot.network.cidr_ip {
            IpNetwork::V4(v4) => {
                Ipv4Network::new(v4.ip(), snapshot.network.cidr_prefix as u8).unwrap()
            }
            IpNetwork::V6(_) => panic!("IPv6 not supported"),
        };

        // Build claimed set and assign AllowedIPs per server (first-server-wins)
        let mut claimed: Vec<Ipv4Network> = Vec::new();

        // Servers in created_at ASC order (already sorted from DB query)
        for server in &snapshot.servers {
            let Some(ref endpoint_host) = server.endpoint_host else {
                continue;
            };

            let server_ip = compute_address(&snapshot.network, server.address_offset);
            let server_32: Ipv4Network = Ipv4Network::new(server_ip, 32).unwrap();

            // Build candidate CIDRs
            let mut candidates: Vec<Ipv4Network> = vec![vpn_cidr];

            let routes = snapshot.server_routes.get(&server.id);
            if let Some(routes) = routes {
                for route in routes {
                    if let IpNetwork::V4(v4) = route.route_cidr {
                        candidates.push(v4);
                    }
                }
            }

            if forward_internet && server.forwards_internet_traffic {
                let all: Ipv4Network = "0.0.0.0/0".parse().unwrap();
                let public_ranges = cidr_subtract_many(all, &rfc1918_networks());
                candidates.extend(public_ranges);
            }

            // Subtract already-claimed CIDRs from candidates
            let mut allowed: Vec<Ipv4Network> = Vec::new();
            for candidate in &candidates {
                let remaining = cidr_subtract_many(*candidate, &claimed);
                allowed.extend(remaining);
            }

            // Always include the server's own /32
            if !allowed.iter().any(|a| network_contains(*a, server_32)) {
                allowed.push(server_32);
            }

            // Deduplicate: remove any /32 of this server if already covered
            // (it was added above only if not already contained)

            // Add all allowed to claimed set
            claimed.extend(&allowed);

            let allowed_ips: Vec<String> = allowed.iter().map(|a| a.to_string()).collect();

            writeln!(config).unwrap();
            writeln!(config, "# {}", server.name).unwrap();
            writeln!(config, "[Peer]").unwrap();
            let server_key = &snapshot.keys[&server.key_id];
            writeln!(config, "PublicKey = {}", server_key.public_key).unwrap();
            writeln!(config, "Endpoint = {endpoint_host}:{}", server.endpoint_port).unwrap();
            writeln!(config, "AllowedIPs = {}", allowed_ips.join(", ")).unwrap();
        }

        config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn net(s: &str) -> Ipv4Network {
        s.parse().unwrap()
    }

    fn nets(strs: &[&str]) -> Vec<Ipv4Network> {
        strs.iter().map(|s| net(s)).collect()
    }

    fn sorted(mut v: Vec<Ipv4Network>) -> Vec<Ipv4Network> {
        v.sort_by_key(|n| (ip_to_u32(n.ip()), n.prefix()));
        v
    }

    // -- CIDR math tests -----------------------------------------------------

    #[test_case("10.0.0.0/24", "10.0.0.0/25", &["10.0.0.128/25"] ; "subtract lower half")]
    #[test_case("10.0.0.0/24", "10.0.0.128/25", &["10.0.0.0/25"] ; "subtract upper half")]
    #[test_case("10.0.0.0/24", "192.168.0.0/24", &["10.0.0.0/24"] ; "non overlapping noop")]
    #[test_case("10.0.0.0/24", "10.0.0.0/24", &[] ; "subtract self")]
    #[test_case("10.0.0.0/24", "10.0.0.0/16", &[] ; "subtract supernet")]
    #[test_case("10.0.0.0/24", "10.0.0.0/26", &["10.0.0.64/26", "10.0.0.128/25"] ; "subtract quarter")]
    fn test_cidr_subtract(base: &str, exclude: &str, expected: &[&str]) {
        let result = sorted(cidr_subtract(net(base), net(exclude)));
        let expected = sorted(nets(expected));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_subtract_rfc1918_from_all() {
        let all: Ipv4Network = "0.0.0.0/0".parse().unwrap();
        let result = cidr_subtract_many(all, &rfc1918_networks());
        // Should cover all public IP space. Verify none of the results overlap RFC1918.
        for r in &result {
            for private in &rfc1918_networks() {
                assert!(
                    !network_contains(*private, *r),
                    "{r} is inside private range {private}"
                );
            }
        }
        // Verify total coverage: sum of all result sizes + RFC1918 sizes = 2^32
        let result_size: u64 = result.iter().map(|n| 1u64 << (32 - n.prefix())).sum();
        let private_size: u64 = rfc1918_networks()
            .iter()
            .map(|n| 1u64 << (32 - n.prefix()))
            .sum();
        assert_eq!(result_size + private_size, 1u64 << 32);
    }

    // -- Config generation helpers -------------------------------------------

    fn make_network(cidr: &str, dns: &[&str]) -> Network {
        let v4: Ipv4Network = cidr.parse().unwrap();
        Network {
            id: Uuid::nil(),
            name: "test-net".to_string(),
            cidr_ip: IpNetwork::V4(Ipv4Network::new(v4.ip(), v4.prefix()).unwrap()),
            cidr_prefix: v4.prefix() as i32,
            owner_id: None,
            dns_servers: dns.iter().map(|s| s.to_string()).collect(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_key(id: Uuid, private: &str, public: &str) -> WgKey {
        WgKey {
            id,
            private_key: private.to_string(),
            public_key: public.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_server(
        id: Uuid,
        key_id: Uuid,
        offset: i32,
        forwards: bool,
        host: Option<&str>,
        port: i32,
    ) -> WgServer {
        WgServer {
            id,
            network_id: Uuid::nil(),
            name: format!("server-{offset}"),
            key_id,
            api_token: Uuid::new_v4().to_string(),
            address_offset: offset,
            forwards_internet_traffic: forwards,
            endpoint_host: host.map(str::to_string),
            endpoint_port: port,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_client(id: Uuid, key_id: Uuid, offset: i32) -> WgClient {
        WgClient {
            id,
            network_id: Uuid::nil(),
            name: format!("client-{offset}"),
            key_id,
            address_offset: offset,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_route(server_id: Uuid, cidr: &str) -> WgServerRoute {
        WgServerRoute {
            id: Uuid::new_v4(),
            server_id,
            route_cidr: IpNetwork::V4(cidr.parse().unwrap()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_snapshot(
        network: Network,
        servers: Vec<WgServer>,
        keys: Vec<WgKey>,
        routes: HashMap<Uuid, Vec<WgServerRoute>>,
    ) -> NetworkSnapshot {
        let keys = keys.into_iter().map(|k| (k.id, k)).collect();
        NetworkSnapshot {
            network,
            servers,
            keys,
            server_routes: routes,
        }
    }

    // -- Config generation tests ---------------------------------------------

    #[test]
    fn test_single_server_split_tunnel() {
        let network = make_network("10.0.1.0/24", &["1.1.1.1", "8.8.8.8"]);
        let sk = Uuid::new_v4();
        let ck = Uuid::new_v4();
        let sid = Uuid::new_v4();

        let server = make_server(sid, sk, 1, false, Some("vpn.example.com"), 51820);
        let skey = make_key(sk, "server-priv", "server-pub");
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 2);

        let snapshot = make_snapshot(network, vec![server], vec![skey], HashMap::new());
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        assert!(config.contains("PrivateKey = client-priv"));
        assert!(config.contains("Address = 10.0.1.2/24"));
        assert!(!config.contains("DNS ="));
        assert!(config.contains("PublicKey = server-pub"));
        assert!(config.contains("Endpoint = vpn.example.com:51820"));
        assert!(config.contains("AllowedIPs = 10.0.1.0/24"));
    }

    #[test]
    fn test_single_server_full_tunnel() {
        let network = make_network("10.0.1.0/24", &[]);
        let sk = Uuid::new_v4();
        let ck = Uuid::new_v4();
        let sid = Uuid::new_v4();

        let server = make_server(sid, sk, 1, true, Some("vpn.example.com"), 51820);
        let skey = make_key(sk, "server-priv", "server-pub");
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 2);

        let snapshot = make_snapshot(network, vec![server], vec![skey], HashMap::new());
        let config = client.wg_quick_config(&ckey, &snapshot, true);

        // Should NOT have a DNS line (empty dns_servers)
        assert!(!config.contains("DNS ="));
        // Should have public IP ranges (non-RFC1918) + VPN CIDR
        assert!(config.contains("10.0.1.0/24"));
        // Should not contain bare 0.0.0.0/0 (RFC1918 subtracted)
        // But should contain public ranges
        assert!(!config.contains("AllowedIPs = 0.0.0.0/0"));
    }

    #[test]
    fn test_single_server_forward_internet_split_tunnel() {
        // forward_internet=false means even if server forwards, client doesn't request it
        let network = make_network("10.0.1.0/24", &[]);
        let sk = Uuid::new_v4();
        let ck = Uuid::new_v4();
        let sid = Uuid::new_v4();

        let server = make_server(sid, sk, 1, true, Some("vpn.example.com"), 51820);
        let skey = make_key(sk, "server-priv", "server-pub");
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 2);

        let snapshot = make_snapshot(network, vec![server], vec![skey], HashMap::new());
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        // Only VPN CIDR, no public ranges
        assert!(config.contains("AllowedIPs = 10.0.1.0/24"));
    }

    #[test]
    fn test_two_servers_first_wins() {
        let network = make_network("10.0.1.0/24", &[]);
        let sk1 = Uuid::new_v4();
        let sk2 = Uuid::new_v4();
        let ck = Uuid::new_v4();
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();

        let mut s1 = make_server(sid1, sk1, 1, false, Some("s1.example.com"), 51820);
        let mut s2 = make_server(sid2, sk2, 2, false, Some("s2.example.com"), 51821);
        // Ensure created_at ordering
        s1.created_at = Utc::now() - chrono::Duration::hours(1);
        s2.created_at = Utc::now();

        let skey1 = make_key(sk1, "s1-priv", "s1-pub");
        let skey2 = make_key(sk2, "s2-priv", "s2-pub");
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 3);

        let snapshot = make_snapshot(
            network,
            vec![s1, s2],
            vec![skey1, skey2],
            HashMap::new(),
        );
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        // First server gets the full network CIDR
        // Second server gets only its /32
        let lines: Vec<&str> = config.lines().collect();
        let allowed1 = lines.iter().find(|l| l.contains("s1.example.com")).unwrap();
        let _ = allowed1; // endpoint line

        // Find AllowedIPs lines — they follow after each Endpoint
        let mut peer_sections: Vec<Vec<&str>> = Vec::new();
        let mut current: Option<Vec<&str>> = None;
        for line in &lines {
            if line.starts_with("[Peer]") {
                if let Some(section) = current.take() {
                    peer_sections.push(section);
                }
                current = Some(Vec::new());
            }
            if let Some(ref mut section) = current {
                section.push(line);
            }
        }
        if let Some(section) = current {
            peer_sections.push(section);
        }

        assert_eq!(peer_sections.len(), 2);

        // First peer (s1): should have 10.0.1.0/24
        let p1_allowed = peer_sections[0]
            .iter()
            .find(|l| l.starts_with("AllowedIPs"))
            .unwrap();
        assert!(p1_allowed.contains("10.0.1.0/24"));

        // Second peer (s2): should have 10.0.1.2/32 (its own IP only)
        let p2_allowed = peer_sections[1]
            .iter()
            .find(|l| l.starts_with("AllowedIPs"))
            .unwrap();
        assert!(p2_allowed.contains("10.0.1.2/32"));
        assert!(!p2_allowed.contains("10.0.1.0/24"));
    }

    #[test]
    fn test_two_servers_explicit_routes_no_overlap() {
        let network = make_network("10.0.1.0/24", &[]);
        let sk1 = Uuid::new_v4();
        let sk2 = Uuid::new_v4();
        let ck = Uuid::new_v4();
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();

        let mut s1 = make_server(sid1, sk1, 1, false, Some("s1.example.com"), 51820);
        let mut s2 = make_server(sid2, sk2, 2, false, Some("s2.example.com"), 51821);
        s1.created_at = Utc::now() - chrono::Duration::hours(1);
        s2.created_at = Utc::now();

        let skey1 = make_key(sk1, "s1-priv", "s1-pub");
        let skey2 = make_key(sk2, "s2-priv", "s2-pub");
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 3);

        let mut routes = HashMap::new();
        routes.insert(sid1, vec![make_route(sid1, "172.16.0.0/24")]);
        routes.insert(sid2, vec![make_route(sid2, "172.17.0.0/24")]);

        let snapshot = make_snapshot(network, vec![s1, s2], vec![skey1, skey2], routes);
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        // s1 gets VPN CIDR + 172.16.0.0/24
        // s2 gets its /32 + 172.17.0.0/24 (VPN CIDR already claimed by s1)
        assert!(config.contains("172.16.0.0/24"));
        assert!(config.contains("172.17.0.0/24"));
    }

    #[test]
    fn test_two_servers_overlapping_routes() {
        let network = make_network("10.0.1.0/24", &[]);
        let sk1 = Uuid::new_v4();
        let sk2 = Uuid::new_v4();
        let ck = Uuid::new_v4();
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();

        let mut s1 = make_server(sid1, sk1, 1, false, Some("s1.example.com"), 51820);
        let mut s2 = make_server(sid2, sk2, 2, false, Some("s2.example.com"), 51821);
        s1.created_at = Utc::now() - chrono::Duration::hours(1);
        s2.created_at = Utc::now();

        let skey1 = make_key(sk1, "s1-priv", "s1-pub");
        let skey2 = make_key(sk2, "s2-priv", "s2-pub");
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 3);

        let mut routes = HashMap::new();
        // Both servers claim the same route
        routes.insert(sid1, vec![make_route(sid1, "172.16.0.0/16")]);
        routes.insert(sid2, vec![make_route(sid2, "172.16.0.0/16")]);

        let snapshot = make_snapshot(network, vec![s1, s2], vec![skey1, skey2], routes);
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        // First server wins the route; count occurrences
        let allowed_lines: Vec<&str> = config
            .lines()
            .filter(|l| l.starts_with("AllowedIPs"))
            .collect();
        assert_eq!(allowed_lines.len(), 2);
        // First peer has 172.16.0.0/16
        assert!(allowed_lines[0].contains("172.16.0.0/16"));
        // Second peer should NOT have 172.16.0.0/16
        assert!(!allowed_lines[1].contains("172.16.0.0/16"));
    }

    #[test]
    fn test_server_without_endpoint_skipped() {
        let network = make_network("10.0.1.0/24", &[]);
        let sk = Uuid::new_v4();
        let ck = Uuid::new_v4();
        let sid = Uuid::new_v4();

        let server = make_server(sid, sk, 1, false, None, 51820);
        let skey = make_key(sk, "server-priv", "server-pub");
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 2);

        let snapshot = make_snapshot(network, vec![server], vec![skey], HashMap::new());
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        assert!(!config.contains("[Peer]"));
    }

    #[test]
    fn test_dns_included_when_forwarding() {
        let network = make_network("10.0.1.0/24", &["1.1.1.1", "8.8.8.8"]);
        let ck = Uuid::new_v4();
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 2);

        let snapshot = make_snapshot(network, vec![], vec![], HashMap::new());
        let config = client.wg_quick_config(&ckey, &snapshot, true);

        assert!(config.contains("DNS = 1.1.1.1, 8.8.8.8"));
    }

    #[test]
    fn test_dns_excluded_without_forwarding() {
        let network = make_network("10.0.1.0/24", &["1.1.1.1", "8.8.8.8"]);
        let ck = Uuid::new_v4();
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 2);

        let snapshot = make_snapshot(network, vec![], vec![], HashMap::new());
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        assert!(!config.contains("DNS ="));
    }

    #[test]
    fn test_empty_dns_no_line() {
        let network = make_network("10.0.1.0/24", &[]);
        let ck = Uuid::new_v4();
        let ckey = make_key(ck, "client-priv", "client-pub");
        let client = make_client(Uuid::new_v4(), ck, 2);

        let snapshot = make_snapshot(network, vec![], vec![], HashMap::new());
        let config = client.wg_quick_config(&ckey, &snapshot, false);

        assert!(!config.contains("DNS"));
    }
}
