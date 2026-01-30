# wirewarden daemon

The wirewarden daemon manages WireGuard interfaces on a server by polling the wirewarden API for configuration updates. It uses netlink APIs directly (wireguard-uapi + rtnetlink) — no `wg` or `ip` commands needed.

## Architecture

The daemon runs as a systemd service. Each polling cycle:

1. Reads `/etc/wirewarden/daemon.toml` for registered servers
2. Fetches desired configuration from each server's API endpoint
3. Ensures the WireGuard interface exists, is configured, and has the correct peers
4. If the API returns 401/404 (token revoked or server deleted), tears down the interface and removes the config entry

## Installation

```bash
cargo build -p wirewarden-daemon --profile distribute
sudo cp target/distribute/wirewarden-daemon /usr/local/bin/wirewarden
sudo cp doc/wirewarden-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wirewarden-daemon
```

## Usage

### `wirewarden connect`

Registers a new server connection by appending to the daemon config file.

```
wirewarden connect \
  --api-host https://vpn.example.com \
  --api-token xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --interface wg0
```

| Flag | Default | Description |
|------|---------|-------------|
| `--api-host` | (required) | API server base URL |
| `--api-token` | (required) | Server API token (UUID) |
| `--interface` | auto (wg0, wg1, …) | WireGuard interface name |
| `-c`, `--config` | `/etc/wirewarden/daemon.toml` | Config file path |

### `wirewarden daemon`

Runs the polling daemon. Typically launched by systemd.

```
wirewarden daemon --interval 30
```

| Flag | Default | Description |
|------|---------|-------------|
| `-c`, `--config` | `/etc/wirewarden/daemon.toml` | Config file path |
| `-i`, `--interval` | 30 | Polling interval in seconds |

## Config File

`/etc/wirewarden/daemon.toml`:

```toml
[[servers]]
api_host = "https://vpn.example.com"
api_token = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
interface = "wg0"

[[servers]]
api_host = "https://vpn2.example.com"
api_token = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
interface = "wg1"
```

## Connect Command from API

When creating a server in the wirewarden admin UI, the API returns a `connect_command` field if `PUBLIC_URL` is set on the API server:

```
wirewarden connect --api-host https://vpn.example.com --api-token <token>
```

Set `PUBLIC_URL` as an environment variable for the API server to enable this.

## Auto-cleanup

If the API returns HTTP 401 (token revoked) or 404 (server deleted) during a polling cycle, the daemon will:

1. Remove the WireGuard interface
2. Remove the `[[servers]]` entry from `daemon.toml`
3. Log a warning
