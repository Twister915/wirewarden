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

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::{debug, error, info, warn};
use wirewarden_daemon::{config, netlink, reconcile};

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(distribute)]
    {
        fmt().json().with_env_filter(filter).init();
    }

    #[cfg(not(distribute))]
    {
        fmt().pretty().with_env_filter(filter).init();
    }
}

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(version = env!("GIT_VERSION"))]
#[command(about = "WireGuard configuration management for wirewarden servers")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the configuration daemon (systemd entrypoint)
    Daemon {
        /// Path to the configuration file
        #[arg(short, long, default_value = "/etc/wirewarden/daemon.toml")]
        config: PathBuf,

        /// Polling interval in seconds
        #[arg(short, long, default_value_t = 30)]
        interval: u64,
    },

    /// Register a new server connection
    Connect {
        /// API server base URL
        #[arg(long)]
        api_host: String,

        /// Server API token (UUID)
        #[arg(long)]
        api_token: String,

        /// Path to the configuration file
        #[arg(short, long, default_value = "/etc/wirewarden/daemon.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Command::Daemon { config, interval } => run_daemon(config, interval).await,
        Command::Connect {
            api_host,
            api_token,
            config,
        } => run_connect(config, api_host, api_token).await,
    }
}

async fn run_daemon(
    config_path: PathBuf,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        config = %config_path.display(),
        interval = interval_secs,
        version = env!("GIT_VERSION"),
        "starting wirewarden daemon"
    );

    let mut daemon_config = config::load(&config_path).await?;

    if daemon_config.servers.is_empty() {
        warn!("no servers configured — use `wirewarden connect` to add one");
    } else {
        info!(
            server_count = daemon_config.servers.len(),
            "loaded server configuration"
        );
    }

    let mut interfaces: Vec<String> = config::assign_interfaces(&daemon_config)
        .into_iter()
        .map(|(_, name)| name)
        .collect();

    let client = reqwest::Client::new();
    let interval = Duration::from_secs(interval_secs);

    let mut shutdown = std::pin::pin!(shutdown_signal());

    info!("entering main poll loop");
    let mut cycle: u64 = 0;

    loop {
        cycle += 1;
        debug!(cycle, "poll cycle start");

        reconcile::reconcile_all::<netlink::CurrentPlatform>(
            &client,
            &config_path,
            &mut daemon_config,
            &mut interfaces,
        )
        .await;

        debug!(cycle, interval = interval_secs, "sleeping until next cycle");

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = &mut shutdown => {
                info!("received shutdown signal");
                break;
            }
        }

        // Reload config each cycle in case `connect` appended entries
        match config::load(&config_path).await {
            Ok(fresh) => {
                let old_count = daemon_config.servers.len();
                let new_count = fresh.servers.len();
                if new_count != old_count {
                    info!(
                        old_count,
                        new_count,
                        "config reloaded, server count changed"
                    );
                    // Re-assign interfaces for any new entries
                    interfaces = config::assign_interfaces(&fresh)
                        .into_iter()
                        .map(|(_, name)| name)
                        .collect();
                } else {
                    debug!(server_count = new_count, "config reloaded, no changes");
                }
                daemon_config = fresh;
            }
            Err(e) => error!(error = %e, "failed to reload config, using previous"),
        }
    }

    teardown_interfaces::<netlink::CurrentPlatform>(&interfaces).await;
    info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

async fn teardown_interfaces<P: netlink::Platform>(interfaces: &[String]) {
    if interfaces.is_empty() {
        return;
    }

    info!(count = interfaces.len(), "removing managed interfaces");
    for interface in interfaces {
        match P::remove_interface(interface).await {
            Ok(()) => info!(interface = %interface, "removed interface"),
            Err(e) => warn!(interface = %interface, error = %e, "failed to remove interface"),
        }
    }
}

async fn run_connect(
    config_path: PathBuf,
    api_host: String,
    api_token: String,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        config = %config_path.display(),
        api_host = %api_host,
        "connecting new server"
    );

    let mut daemon_config = config::load(&config_path).await?;

    let entry = config::ServerEntry {
        api_host,
        api_token,
    };

    config::validate_new_entry(&daemon_config, &entry)?;

    daemon_config.servers.push(entry);
    config::save(&config_path, &daemon_config).await?;

    info!(
        config = %config_path.display(),
        "server added — restart the daemon to apply"
    );
    Ok(())
}
