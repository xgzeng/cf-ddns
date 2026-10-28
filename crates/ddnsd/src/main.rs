mod config;

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use ddns_clients::{
    CloudflareProvider, DnsProvider, Updater, UpdaterOptions,
    detect::{self, DetectOptions},
};

use config::{Config, ProviderConfig};

/// Dynamic DNS daemon: keeps a domain's A/AAAA records pointed at this host.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the YAML config file.
    #[arg(short, long, default_value = "/etc/ddnsd.yaml")]
    config: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let config = Config::load(&args.config)
        .with_context(|| format!("load {} failed", args.config.display()))?;

    match &config.provider {
        ProviderConfig::Cloudflare { api_token, zone } => {
            run(
                CloudflareProvider::new(api_token.as_str(), zone.as_str())?,
                &config,
            )
            .await
        }
    }
}

async fn run<P: DnsProvider>(provider: P, config: &Config) -> Result<()> {
    let mut updater = Updater::new(
        provider,
        config.domain(),
        UpdaterOptions {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            ttl: config.ttl(),
            max_records: config.max_records,
        },
    );
    let detect_options = DetectOptions {
        ipv4: config.ipv4,
        ipv6: config.ipv6,
    };

    loop {
        if let Err(err) = update_once(&detect_options, &mut updater).await {
            log::warn!("update dns record failed: {err:?}");
        }
        tokio::time::sleep(Duration::from_secs(config.interval)).await;
    }
}

async fn update_once<P: DnsProvider>(
    detect_options: &DetectOptions,
    updater: &mut Updater<P>,
) -> Result<()> {
    let addrs = detect::detect_public_ips(detect_options).await;
    if addrs.is_empty() {
        log::warn!("no public ip address found");
        return Ok(());
    }
    updater.update_ips(&addrs).await?;
    Ok(())
}
