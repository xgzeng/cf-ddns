mod cf_client;
mod network;

use anyhow::{Context, Result};
use cf_client::{DDnsClient, DDnsClientOption};
use network::{get_current_ipv4, get_current_ipv6, get_current_ipv6_local};

use clap;
use serde_yaml;

use std::{fs::File, net::IpAddr, time::Duration};

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
    ttl: Option<u32>,
    validation_ips: Option<Vec<IpAddr>>,
}

impl Config {
    fn load<P>(path: P) -> Result<Config>
    where
        P: AsRef<std::path::Path>,
    {
        // read config file
        let cfg_reader = File::open(path).context("open config file failed")?;
        let config: Config = serde_yaml::from_reader(cfg_reader)?;

        Ok(config)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = clap::Command::new("cf-ddns")
        .arg(
            clap::Arg::new("config")
                .short('c')
                .default_value("/etc/cf-ddns.yaml"),
        )
        .get_matches();

    // command line argument
    let config_file = args.get_one::<String>("config").unwrap();

    // read config file
    let config = Config::load(config_file)?;

    let mut ddns_client = DDnsClient::new(
        config.api_token.clone(),
        config.zone.clone(),
        config.domain.clone(),
        DDnsClientOption {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            ttl: config.ttl,
            max_count: 2,
        },
    )
    .await?;

    loop {
        // loop once
        match update_once(&config, &mut ddns_client).await {
            Ok(_) => (),
            Err(err) => log::warn!("update dns record failed: {}, {}", err, err.root_cause()),
        }
        tokio::time::sleep(Duration::from_secs(config.interval)).await;
    }
}

async fn update_once(config: &Config, ddns_client: &mut DDnsClient) -> Result<()> {
    // get my ip by online service
    // let mut reqw_client = ReqwClient::new();
    // let addrs = match query_local_ips(&mut reqw_client, config.ipv4, config.ipv6).await {
    //     Ok(addrs) => addrs,
    //     Err(err) => {
    //         log::warn!("query local ips failed: {}", err);
    //         return Ok(());
    //     }
    // };
    // log::info!("local ips: {:?}", addrs);
    let addrs = network::rtnetlink_get_addresses(config.ipv4, config.ipv6).await?;
    ddns_client.update_ips(&addrs).await?;
    Ok(())
}

fn yes() -> bool {
    true
}

fn default_duration() -> u64 {
    60
}
