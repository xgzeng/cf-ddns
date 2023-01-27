mod network;

use anyhow::{Context, Result};
use network::{get_current_ipv4, get_current_ipv6_local, get_record, get_zone, update_record};

use clap;
use serde_yaml;

use std::{fs::File, net::IpAddr, time::Duration};

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
    #[serde(default = "yes")]
    ipv6: bool,
    #[serde(default = "default_duration")]
    interval: u64,
    // #[serde(default = 10)]
    ttl: Option<u32>,
}

impl Config {
    fn load<P>(path: P) -> Result<Config>
    where P : AsRef<std::path::Path> {
        // read config file
        let cfg_reader = File::open(path).context("open config file failed")?;
        let config: Config = serde_yaml::from_reader(cfg_reader)?;

        Ok(config)
    }
}

struct Zone {
    zone_name: String,
    domain_name: String,
    zone_id: Option<String>, // cloudflare api zone id
    local_ips: Vec<IpAddr>,
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

    // read config file
    let config = Config::load(config_file)?;

    let mut zone = Zone {
        zone_name: config.zone.clone(),
        domain_name: config.domain.clone(),
        zone_id: None,
        local_ips: vec![],
    };

    let mut cf_client = CfClient::new(
        Credentials::UserAuthToken {
            token: config.api_token.clone(),
        },
        HttpApiClientConfig::default(),
        Environment::Production,
    )?;

    loop {
        // loop once
        log::info!("update_once");
        match update_once(&config, &mut zone, &mut cf_client).await {
            Ok(_) => (),
            Err(err) => log::warn!("update failed: {}", err),
        }

        tokio::time::sleep(Duration::from_secs(config.interval)).await;
    }
}

async fn update_once(config: &Config, zone: &mut Zone, cf_client: &mut CfClient) -> Result<()> {
    let mut reqw_client = ReqwClient::new();

    // query local ips
    let addrs = query_local_ip(&mut reqw_client, config.ipv4, config.ipv6).await?;
    log::debug!("local ips: {:?}", addrs);

    if addrs == zone.local_ips {
        // ip address not changed
        log::info!("ip address no change");
        return Ok(());
    }

    if zone.zone_id.is_none() {
        let zid = get_zone(zone.zone_name.clone(), cf_client).await?;
        log::debug!("got zone id for {}: {}", zone.zone_name, zid);
        zone.zone_id = Some(zid)
    }

    for addr in &addrs {
        update_ip(
            cf_client,
            zone.zone_id.as_ref().unwrap(),
            &zone.domain_name,
            addr,
            config.ttl,
        )
        .await?
    }

    zone.local_ips = addrs;
    Ok(())
}

async fn update_ip(
    cf_client: &mut CfClient,
    zone_id: &str,
    domain: &str,
    ip: &IpAddr,
    ttl: Option<u32>,
) -> Result<()> {
    log::info!("update_ip: {} {} ttl={:?}", domain, ip, ttl);

    match ip {
        IpAddr::V4(ip_v4) => {
            let record_id = get_record(zone_id, domain, network::A_RECORD, cf_client)
                .await
                .context("couldn't find A record!")?;
            log::debug!("got A record id {}", record_id);

            update_record(
                zone_id,
                &record_id,
                domain,
                DnsContent::A {
                    content: ip_v4.clone(),
                },
                ttl,
                cf_client,
            )
            .await?;

            log::info!("update A record to {}", ip_v4);
        }
        IpAddr::V6(ip_v6) => {
            let record_id = get_record(zone_id, domain, network::AAAA_RECORD, cf_client)
                .await
                .context("couldn't find AAAA record!")?;
            log::debug!("got AAAA record id {}", record_id);
            update_record(
                zone_id,
                &record_id,
                domain,
                DnsContent::AAAA {
                    content: *ip_v6,
                },
                ttl,
                cf_client,
            )
            .await?;
            log::debug!("update AAAA record to {}", ip_v6);
        }
    }
    Ok(())
}

async fn query_local_ip(reqw_client: &mut ReqwClient, v4: bool, v6: bool) -> Result<Vec<IpAddr>> {
    let mut addrs: Vec<IpAddr> = vec![];

    if v4 {
        let addr = get_current_ipv4(reqw_client).await?;
        log::info!("fetched current IP: {}", addr.to_string());
        addrs.push(IpAddr::V4(addr))
    }

    if v6 {
        let addrs_v6 = get_current_ipv6_local();
        if !addrs_v6.is_empty() {
            addrs.push(IpAddr::V6(addrs_v6[0]))
        }
    }

    Ok(addrs)
}

fn yes() -> bool {
    true
}

fn default_duration() -> u64 {
    60
}
