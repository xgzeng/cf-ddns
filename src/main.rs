#![feature(ip)]

mod network;

use anyhow::{Context, Result};
use network::{get_current_ipv4, get_current_ipv6_local, get_record, get_zone, update_record};

use clap;
use serde_yaml;

use std::{
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::time::interval;

use cloudflare::{
    endpoints::dns::DnsContent,
    framework::{
        async_api::Client as CfClient, auth::Credentials, Environment, HttpApiClientConfig,
    },
};
use reqwest::Client as ReqwClient;

#[derive(serde::Serialize, serde::Deserialize)]
struct Config {
    api_token: String,
    zone: String,
    domain: String,
    #[serde(default = "yes")]
    ipv4: bool,
    #[serde(default = "no")]
    ipv6: bool,
    #[serde(default = "default_duration")]
    interval: u64,
}

struct Zone {
    zone_name: String,
    domain_name: String,
    zone_id: Option<String>, // cloudflare api zone id
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = clap::Command::new("cloudflare-ddns")
        .arg(
            clap::Arg::new("config")
                .short('c')
                .takes_value(true)
                .default_value("/etc/cloudflare-ddns.yaml"),
        )
        .get_matches();

    // command line argument
    let config_file = args.value_of("config").unwrap();

    let config_string = read_to_string(&config_file).context("couldn't read config file")?;

    let config: Config = serde_yaml::from_str(&config_string)?;
    let mut zone = Zone {
        zone_name: config.zone.clone(),
        domain_name: config.domain.clone(),
        zone_id: None,
        v4: None,
        v6: None,
    };

    let mut interval = interval(Duration::new(config.interval, 0));
    let mut reqw_client = ReqwClient::new();
    let mut cf_client = CfClient::new(
        Credentials::UserAuthToken {
            token: config.api_token.clone(),
        },
        HttpApiClientConfig::default(),
        Environment::Production,
    )?;

    loop {
        if zone.zone_id.is_none() {
            match get_zone(zone.zone_name.clone(), &mut cf_client).await {
                Ok(id) => {
                    log::info!("got zone id for {}: {}", zone.zone_name, id);
                    zone.zone_id = Some(id);
                }
                Err(err) => {
                    log::warn!("got zone id error: {}", err);
                    interval.tick().await;
                    continue;
                }
            }
        }

        if config.ipv4 {
            let update_result = update_ipv4(&mut zone, &mut reqw_client, &mut cf_client).await;
            match update_result {
                Ok(_) => (),
                Err(err) => log::warn!("update failed: {}", err),
            }
        }

        if config.ipv6 {
            let update_result = update_ipv6(&mut zone, &mut reqw_client, &mut cf_client).await;
            match update_result {
                Ok(_) => (),
                Err(err) => log::warn!("update failed: {}", err),
            }
        }

        interval.tick().await;
    }
}

async fn update_ip(
    cf_client: &mut CfClient,
    zone_id: &str,
    domain: &str,
    ip: IpAddr,
) -> Result<()> {
    match ip {
        IpAddr::V4(ip_v4) => {
            let record_id = get_record(zone_id, domain, network::A_RECORD, cf_client)
                .await
                .context("couldn't find record!")?;
            log::info!("got record id {}", record_id);

            update_record(
                zone_id,
                &record_id,
                domain,
                DnsContent::A { content: ip_v4 },
                cf_client,
            )
            .await?;
        }
        IpAddr::V6(ip_v6) => {
            let record_id = get_record(zone_id, domain, network::AAAA_RECORD, cf_client)
                .await
                .context("couldn't find record!")?;
            log::info!("got record id {}", record_id);
            update_record(
                zone_id,
                &record_id,
                domain,
                DnsContent::AAAA { content: ip_v6 },
                cf_client,
            )
            .await?;
        }
    }
    Ok(())
}

async fn update_ipv4(
    zone: &mut Zone,
    reqw_client: &mut ReqwClient,
    cf_client: &mut CfClient,
) -> Result<()> {
    let current = get_current_ipv4(reqw_client).await?;
    log::info!("fetched current IP: {}", current.to_string());

    if let Some(old) = zone.v4 {
        if old == current {
            log::debug!("ipv4 unchanged, continuing...");
            return Ok(());
        }
    }

    let zone_id = zone.zone_id.as_ref().unwrap();
    log::info!("ipv4 changed, setting record");
    update_ip(cf_client, zone_id, &zone.domain_name, IpAddr::V4(current)).await?;
    zone.v4 = Some(current);

    Ok(())
}

async fn update_ipv6(
    zone: &mut Zone,
    reqw_client: &mut ReqwClient,
    cf_client: &mut CfClient,
) -> Result<()> {
    let zone_id = zone.zone_id.as_ref().unwrap();

    // let current = get_current_ipv6(reqw_client).await?;
    let local_ips = get_current_ipv6_local();
    if local_ips.is_empty() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "no ipv6 address");
        return Err(anyhow::Error::new(err));
    }

    let current = local_ips[0];
    log::info!("fetched current IP: {}", current.to_string());

    if let Some(old) = zone.v6 {
        if old == current {
            log::debug!("ipv6 unchanged, continuing...");
            return Ok(());
        }
    }

    log::debug!("ipv6 changed, setting record");
    update_ip(cf_client, zone_id, &zone.domain_name, IpAddr::V6(current)).await?;
    log::info!("ipv6 updated to {}", current);
    zone.v6 = Some(current);

    Ok(())
}

fn yes() -> bool {
    true
}

fn no() -> bool {
    false
}

fn default_duration() -> u64 {
    60
}
