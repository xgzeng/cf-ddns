mod network;

use anyhow::{Context, Result};
use clap;
use directories_next::ProjectDirs;
use network::{get_current_ipv4, get_current_ipv6, get_record, get_zone, update_record};
use serde::{Deserialize, Serialize};
use serde_yaml;

use std::{
    fs::{create_dir_all, read_to_string, File},
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
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

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize, Default)]
struct Cache {
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = clap::App::new("cloudflare-ddns-service")
        .arg(clap::Arg::new("config").short('c').takes_value(true))
        .get_matches();

    // project dirs
    let dirs = ProjectDirs::from("re", "jcg", "cloudflare-ddns-service")
        .context("Couldn't find project directories! Is $HOME set?")?;
    
    // command line argument
    let config_file = match args.value_of("config") {
        Some(config_file) => std::path::PathBuf::from(config_file),
        None => dirs.config_dir().join("config.yaml"),
    };

    let config_string = read_to_string(&config_file).context(format!(
        "couldn't read config file! {}",
        config_file.to_str().unwrap()
    ))?;

    let config: Config = serde_yaml::from_str(&config_string)?;
    let cache_path = dirs.cache_dir().join("cache.yaml");
    let mut cache = match read_to_string(&cache_path) {
        Ok(cache) => serde_yaml::from_str(&cache)?,
        Err(_) => {
            create_dir_all(dirs.cache_dir())?;
            Cache::default()
        }
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
    let zone = get_zone(config.zone.clone(), &mut cf_client).await?;
    loop {
        update(
            &config,
            &mut cache,
            &cache_path,
            &zone,
            &mut reqw_client,
            &mut cf_client,
        )
        .await?;
        interval.tick().await;
    }
}

async fn update(
    config: &Config,
    cache: &mut Cache,
    cache_path: &PathBuf,
    zone: &str,
    reqw_client: &mut ReqwClient,
    cf_client: &mut CfClient,
) -> Result<()> {
    if config.ipv4 {
        let current = get_current_ipv4(reqw_client).await?;
        log::debug!("fetched current IP: {}", current.to_string());
        match cache.v4 {
            Some(old) if old == current => {
                log::debug!("ipv4 unchanged, continuing...");
            }
            _ => {
                log::debug!("ipv4 changed, setting record");
                let rid = get_record(zone, config.domain.clone(), network::A_RECORD, cf_client)
                    .await
                    .context("couldn't find record!")?;
                log::debug!("got record ID {}", rid);
                update_record(
                    zone,
                    &rid,
                    &config.domain,
                    DnsContent::A { content: current },
                    cf_client,
                )
                .await?;
                cache.v4 = Some(current);
                write_cache(cache, cache_path)?;
            }
        }
    }
    if config.ipv6 {
        let current = get_current_ipv6(reqw_client).await?;
        log::debug!("fetched current IP: {}", current.to_string());
        match cache.v6 {
            Some(old) if old == current => {
                log::debug!("ipv6 unchanged, continuing...")
            }
            _ => {
                log::debug!("ipv4 changed, setting record");
                let rid = get_record(zone, config.domain.clone(), network::AAAA_RECORD, cf_client)
                    .await
                    .context("couldn't find record!")?;
                log::debug!("got record ID {}", rid);
                update_record(
                    zone,
                    &rid,
                    &config.domain,
                    DnsContent::AAAA { content: current },
                    cf_client,
                )
                .await?;
                cache.v6 = Some(current);
                write_cache(cache, cache_path)?;
            }
        }
    }
    Ok(())
}

fn write_cache(cache: &mut Cache, cache_path: &PathBuf) -> Result<()> {
    serde_yaml::to_writer(File::create(cache_path)?, cache)?;
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
