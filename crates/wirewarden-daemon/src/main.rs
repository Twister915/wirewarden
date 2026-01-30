use std::time::Duration;

use clap::Parser;
use tracing::info;

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
#[command(about = "WireGuard configuration daemon for wirewarden servers")]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, default_value = "/etc/wirewarden/daemon.toml")]
    config: String,

    /// Polling interval in seconds
    #[arg(short, long, default_value_t = 30)]
    interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();

    info!(config = %args.config, interval = args.interval, "starting wirewarden-daemon");

    let interval = Duration::from_secs(args.interval);

    loop {
        info!("polling for configuration updates");
        // TODO: fetch config from API, apply to WireGuard interface
        tokio::time::sleep(interval).await;
    }
}
