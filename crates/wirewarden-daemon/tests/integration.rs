use std::net::SocketAddr;
use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use wirewarden_daemon::config::{self, DaemonToml, ServerEntry};
use wirewarden_daemon::netlink::{Platform, PlatformError};
use wirewarden_daemon::reconcile;
use wirewarden_types::daemon::{DaemonConfig, DaemonNetworkInfo, DaemonPeer, DaemonServerInfo};

// -- Mock platform that records calls --
// Global statics require serial execution for reconcile tests.

static TEST_LOCK: Mutex<()> = Mutex::new(());
static APPLIED: Mutex<Vec<String>> = Mutex::new(Vec::new());
static REMOVED: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct MockPlatform;

impl Platform for MockPlatform {
    async fn ensure_interface(_name: &str) -> Result<(), PlatformError> {
        Ok(())
    }

    async fn remove_interface(name: &str) -> Result<(), PlatformError> {
        REMOVED.lock().unwrap().push(name.to_string());
        Ok(())
    }

    async fn apply_config(name: &str, _config: &DaemonConfig) -> Result<(), PlatformError> {
        APPLIED.lock().unwrap().push(name.to_string());
        Ok(())
    }

    async fn interface_exists(_name: &str) -> Result<bool, PlatformError> {
        Ok(false)
    }
}

/// Acquire the test lock and clear mock state. Hold the returned guard for
/// the duration of the test to prevent interleaving with other reconcile tests.
fn lock_and_clear() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap();
    APPLIED.lock().unwrap().clear();
    REMOVED.lock().unwrap().clear();
    guard
}

fn applied() -> Vec<String> {
    APPLIED.lock().unwrap().clone()
}

fn removed() -> Vec<String> {
    REMOVED.lock().unwrap().clone()
}

// -- Helpers --

fn sample_daemon_config() -> DaemonConfig {
    DaemonConfig {
        server: DaemonServerInfo {
            id: Uuid::new_v4(),
            name: "test-server".into(),
            private_key: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=".into(), // 32 bytes of 'a'
            public_key: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=".into(),
            address: "10.0.0.1".into(),
            listen_port: 51820,
        },
        network: DaemonNetworkInfo {
            id: Uuid::new_v4(),
            name: "test-network".into(),
            cidr: "10.0.0.0/24".into(),
        },
        peers: vec![DaemonPeer {
            public_key: "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYWE=".into(),
            allowed_ips: vec!["10.0.0.2/32".into()],
            endpoint: None,
        }],
    }
}

/// Spawn a tiny HTTP server that responds to GET /api/daemon/config.
/// Returns (addr, shutdown_sender).
async fn spawn_mock_api(
    status: u16,
    body: &str,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = body.to_string();
    let (tx, mut rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (mut stream, _) = accept.unwrap();
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;

                    let response = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
                _ = &mut rx => break,
            }
        }
    });

    (addr, tx)
}

// -- Tests --

#[tokio::test]
async fn reconcile_applies_config_from_api() {
    let _guard = lock_and_clear();

    let body = serde_json::to_string(&sample_daemon_config()).unwrap();
    let (addr, _shutdown) = spawn_mock_api(200, &body).await;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let config_path = tmp.path().to_path_buf();

    let mut daemon_config = DaemonToml {
        servers: vec![ServerEntry {
            api_host: format!("http://{addr}"),
            api_token: "test-token".into(),
        }],
    };
    let mut interfaces = vec!["wg0".to_string()];

    let client = reqwest::Client::new();
    reconcile::reconcile_all::<MockPlatform>(&client, &config_path, &mut daemon_config, &mut interfaces).await;

    assert_eq!(applied(), vec!["wg0"]);
    assert!(removed().is_empty());
    assert_eq!(daemon_config.servers.len(), 1, "server entry should remain");
}

#[tokio::test]
async fn reconcile_multiple_servers() {
    let _guard = lock_and_clear();

    let body = serde_json::to_string(&sample_daemon_config()).unwrap();
    let (addr1, _s1) = spawn_mock_api(200, &body).await;
    let (addr2, _s2) = spawn_mock_api(200, &body).await;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let config_path = tmp.path().to_path_buf();

    let mut daemon_config = DaemonToml {
        servers: vec![
            ServerEntry {
                api_host: format!("http://{addr1}"),
                api_token: "token-1".into(),
            },
            ServerEntry {
                api_host: format!("http://{addr2}"),
                api_token: "token-2".into(),
            },
        ],
    };
    let mut interfaces = vec!["wg0".to_string(), "wg1".to_string()];

    let client = reqwest::Client::new();
    reconcile::reconcile_all::<MockPlatform>(&client, &config_path, &mut daemon_config, &mut interfaces).await;

    let mut apps = applied();
    apps.sort();
    assert_eq!(apps, vec!["wg0", "wg1"]);
    assert_eq!(daemon_config.servers.len(), 2);
}

#[tokio::test]
async fn reconcile_removes_server_on_401() {
    let _guard = lock_and_clear();

    let (addr, _shutdown) = spawn_mock_api(401, r#"{"error":"unauthorized"}"#).await;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let config_path = tmp.path().to_path_buf();

    // Seed the file so save can overwrite it
    config::save(&config_path, &DaemonToml { servers: vec![] }).await.unwrap();

    let mut daemon_config = DaemonToml {
        servers: vec![ServerEntry {
            api_host: format!("http://{addr}"),
            api_token: "revoked-token".into(),
        }],
    };
    let mut interfaces = vec!["wg0".to_string()];

    let client = reqwest::Client::new();
    reconcile::reconcile_all::<MockPlatform>(&client, &config_path, &mut daemon_config, &mut interfaces).await;

    assert!(applied().is_empty(), "should not apply config on 401");
    assert_eq!(removed(), vec!["wg0"], "should tear down interface");
    assert!(daemon_config.servers.is_empty(), "should remove entry from config");
    assert!(interfaces.is_empty(), "should remove interface from list");

    // Verify file was updated
    let reloaded = config::load(&config_path).await.unwrap();
    assert!(reloaded.servers.is_empty());
}

#[tokio::test]
async fn reconcile_removes_server_on_404() {
    let _guard = lock_and_clear();

    let (addr, _shutdown) = spawn_mock_api(404, r#"{"error":"not found"}"#).await;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let config_path = tmp.path().to_path_buf();
    config::save(&config_path, &DaemonToml { servers: vec![] }).await.unwrap();

    let mut daemon_config = DaemonToml {
        servers: vec![ServerEntry {
            api_host: format!("http://{addr}"),
            api_token: "deleted-server-token".into(),
        }],
    };
    let mut interfaces = vec!["wg0".to_string()];

    let client = reqwest::Client::new();
    reconcile::reconcile_all::<MockPlatform>(&client, &config_path, &mut daemon_config, &mut interfaces).await;

    assert!(applied().is_empty());
    assert_eq!(removed(), vec!["wg0"]);
    assert!(daemon_config.servers.is_empty());
}

#[tokio::test]
async fn reconcile_keeps_server_on_transient_error() {
    let _guard = lock_and_clear();

    let (addr, _shutdown) = spawn_mock_api(500, r#"{"error":"internal"}"#).await;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let config_path = tmp.path().to_path_buf();

    let mut daemon_config = DaemonToml {
        servers: vec![ServerEntry {
            api_host: format!("http://{addr}"),
            api_token: "some-token".into(),
        }],
    };
    let mut interfaces = vec!["wg0".to_string()];

    let client = reqwest::Client::new();
    reconcile::reconcile_all::<MockPlatform>(&client, &config_path, &mut daemon_config, &mut interfaces).await;

    assert!(applied().is_empty());
    assert!(removed().is_empty());
    assert_eq!(daemon_config.servers.len(), 1, "should keep entry for retry");
}

#[tokio::test]
async fn reconcile_mixed_success_and_gone() {
    let _guard = lock_and_clear();

    let body = serde_json::to_string(&sample_daemon_config()).unwrap();
    let (good_addr, _s1) = spawn_mock_api(200, &body).await;
    let (gone_addr, _s2) = spawn_mock_api(404, "{}").await;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let config_path = tmp.path().to_path_buf();
    config::save(&config_path, &DaemonToml { servers: vec![] }).await.unwrap();

    let mut daemon_config = DaemonToml {
        servers: vec![
            ServerEntry {
                api_host: format!("http://{good_addr}"),
                api_token: "good-token".into(),
            },
            ServerEntry {
                api_host: format!("http://{gone_addr}"),
                api_token: "gone-token".into(),
            },
        ],
    };
    let mut interfaces = vec!["wg0".to_string(), "wg1".to_string()];

    let client = reqwest::Client::new();
    reconcile::reconcile_all::<MockPlatform>(&client, &config_path, &mut daemon_config, &mut interfaces).await;

    assert_eq!(applied(), vec!["wg0"]);
    assert_eq!(removed(), vec!["wg1"]);
    assert_eq!(daemon_config.servers.len(), 1);
    assert_eq!(interfaces, vec!["wg0"]);
}

#[tokio::test]
async fn connect_writes_config_and_validates() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("daemon.toml");

    // First entry
    let mut cfg = config::load(&config_path).await.unwrap();
    let entry1 = ServerEntry {
        api_host: "https://vpn1.example.com".into(),
        api_token: "aaaa".into(),
    };
    config::validate_new_entry(&cfg, &entry1).unwrap();
    cfg.servers.push(entry1);
    config::save(&config_path, &cfg).await.unwrap();

    // Reload and add second
    let mut cfg = config::load(&config_path).await.unwrap();
    assert_eq!(cfg.servers.len(), 1);

    let entry2 = ServerEntry {
        api_host: "https://vpn2.example.com".into(),
        api_token: "bbbb".into(),
    };
    config::validate_new_entry(&cfg, &entry2).unwrap();
    cfg.servers.push(entry2);
    config::save(&config_path, &cfg).await.unwrap();

    // Verify
    let cfg = config::load(&config_path).await.unwrap();
    assert_eq!(cfg.servers.len(), 2);

    // Duplicate token rejected
    let dup_token = ServerEntry {
        api_host: "https://vpn3.example.com".into(),
        api_token: "aaaa".into(),
    };
    assert!(config::validate_new_entry(&cfg, &dup_token).is_err());
}

#[tokio::test]
async fn assign_interfaces_sequential() {
    let cfg = DaemonToml {
        servers: vec![
            ServerEntry {
                api_host: "a".into(),
                api_token: "a".into(),
            },
            ServerEntry {
                api_host: "b".into(),
                api_token: "b".into(),
            },
        ],
    };

    let assignments = config::assign_interfaces(&cfg);
    assert_eq!(assignments[0].1, "wg0");
    assert_eq!(assignments[1].1, "wg1");
}

#[tokio::test]
async fn api_fetch_parses_valid_response() {
    let body = serde_json::to_string(&sample_daemon_config()).unwrap();
    let (addr, _shutdown) = spawn_mock_api(200, &body).await;

    let entry = ServerEntry {
        api_host: format!("http://{addr}"),
        api_token: "test-token".into(),
    };

    let client = reqwest::Client::new();
    let result = wirewarden_daemon::api::fetch_config(&client, &entry).await;
    let config = result.unwrap();
    assert_eq!(config.server.name, "test-server");
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.network.cidr, "10.0.0.0/24");
}

#[tokio::test]
async fn api_fetch_returns_unauthorized_on_401() {
    let (addr, _shutdown) = spawn_mock_api(401, "{}").await;

    let entry = ServerEntry {
        api_host: format!("http://{addr}"),
        api_token: "bad-token".into(),
    };

    let client = reqwest::Client::new();
    let result = wirewarden_daemon::api::fetch_config(&client, &entry).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().is_gone());
}
