mod cf_client;
mod myip;

use anyhow::{Context, Result};
use cf_client::{DDnsClient, DDnsClientOption};

use clap;
use serde_yaml;

use std::os::unix::fs::PermissionsExt;
use std::{fs::File, net::IpAddr, time::Duration};

#[derive(serde::Serialize, serde::Deserialize)]
struct Config {
    api_token: String,
    zone: String,
    domain: Option<String>,
    #[serde(default = "yes")]
    ipv4: bool,
    #[serde(default = "yes")]
    ipv6: bool,
    #[serde(default = "default_check_interval")]
    interval: u64,
    #[serde(default = "default_ttl")]
    ttl: u32,
    validation_ips: Option<Vec<IpAddr>>,
}

impl Config {
    fn load<P>(path: P) -> Result<Config>
    where
        P: AsRef<std::path::Path>,
    {
        // check config file permission, should not been readable by other user
        let metadata = std::fs::metadata(&path)?;
        let permissions = metadata.permissions();
        let mode = permissions.mode();
        if mode & 0o077 != 0 {
            return Err(anyhow::anyhow!("config file is readable by others"));
        }

        // read config file
        let cfg_reader = File::open(path)?;
        let mut config: Config = serde_yaml::from_reader(cfg_reader)?;

        if config.domain.is_none() {
            log::info!("domain is not set, use <hostname>.<zone> as domain");
            let domain = format!("{}.{}", hostname::get()?.to_string_lossy(), config.zone);
            config.domain = Some(domain)
        }

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
    let config = Config::load(config_file).context(format!("load {} failed", config_file))?;

    let ttl = if config.ttl == 0 {
        None
    } else {
        Some(config.ttl)
    };

    let mut ddns_client = DDnsClient::new(
        config.api_token.clone(),
        config.zone.clone(),
        config.domain.clone().unwrap(),
        DDnsClientOption {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            ttl,
            max_count: 2,
        },
    )
    .await?;

    loop {
        // loop once
        match update_once(&config, &mut ddns_client).await {
            Ok(_) => (),
            Err(err) => log::warn!("update dns record failed: {:?}", err),
        }
        tokio::time::sleep(Duration::from_secs(config.interval)).await;
    }
}

async fn update_once(config: &Config, ddns_client: &mut DDnsClient) -> Result<()> {
    // get my ip by online service
    //
    // let addrs = match query_local_ips(&mut reqw_client, config.ipv4, config.ipv6).await {
    //     Ok(addrs) => addrs,
    //     Err(err) => {
    //         log::warn!("query local ips failed: {}", err);
    //         return Ok(());
    //     }
    // };
    // log::info!("local ips: {:?}", addrs);
    let my_ip_options = myip::Options {
        ipv4: config.ipv4,
        ipv6: config.ipv6,
    };

    let addrs = myip::try_detect_public_ip(my_ip_options).await;
    if addrs.is_empty() {
        log::warn!("no public ip address found");
        return Ok(());
    }
    ddns_client.update_ips(&addrs).await?;
    Ok(())
}

fn yes() -> bool {
    true
}

fn default_check_interval() -> u64 {
    300
}

fn default_ttl() -> u32 {
    600
}
