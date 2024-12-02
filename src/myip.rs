/// module used to detect public ip addresses
use ipnetwork::IpNetwork;
use std::{
    net::{IpAddr, Ipv6Addr},
    vec,
};

use anyhow::Result;
use reqwest::Client as ReqwClient;

use futures_util::TryStreamExt;

pub struct Options {
    pub ipv4: bool, // enable detection of ipv4 address
    pub ipv6: bool, // enable detection of ipv6 address
}

pub async fn try_detect_public_ip(options: Options) -> Vec<IpAddr> {
    // detect with online service
    match detect_online(&options).await {
        Ok(addrs) => return addrs,
        Err(err) => {
            log::warn!("detect public ip failed: {}", err);
        }
    };

    // detect with netlink on linux
    #[cfg(target_os = "linux")]
    match rtnetlink_get_addresses(&options).await {
        Ok(addrs) => return addrs,
        Err(err) => {
            log::warn!("detect public ip failed: {}", err);
        }
    };

    vec![]
}

// detect public ip address by online service
async fn detect_online(options: &Options) -> Result<Vec<IpAddr>> {
    let reqw_client = ReqwClient::new();

    // https://icanhazip.com
    let mut urls = vec![];
    if options.ipv4 {
        urls.push("https://ipv4.icanhazip.com");
    }
    if options.ipv6 {
        urls.push("https://ipv6.icanhazip.com");
    }

    let mut addrs = vec![];
    for url in urls {
        let addr: IpAddr = reqw_client
            .get(url)
            .send()
            .await?
            .text()
            .await?
            .trim()
            .parse()?;
        addrs.push(addr);
    }
    Ok(addrs)
}

fn is_unicast_global(addr: &Ipv6Addr) -> bool {
    !addr.is_multicast() // is_unicast
        && !addr.is_loopback()
        && !((addr.segments()[0] & 0xffc0) == 0xfe80) // !is_unicast_link_local
        && !((addr.segments()[0] & 0xfe00) == 0xfc00) // !is_unique_local
        && !addr.is_unspecified()
        && !((addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8))
}

// pub fn get_current_ipv6_local(max_count: u8) -> Vec<Ipv6Addr> {
//     pnet_datalink::interfaces()
//         .into_iter()
//         .flat_map(|net_if| net_if.ips)
//         .filter_map(|ip| match ip {
//             IpNetwork::V6(addr_v6) if is_unicast_global(&addr_v6.ip()) => {
//                 Some(addr_v6.ip().clone())
//             }
//             _ => None,
//         })
//         .take(max_count as usize)
//         .collect()
// }

// use rtlink to retrieve local ip addresses
#[cfg(target_os = "linux")]
pub async fn rtnetlink_get_addresses(options: &Options) -> Result<Vec<IpAddr>> {
    use netlink_packet_route::{
        address::{AddressAttribute, AddressScope},
        AddressFamily,
    };
    
    let (conn, handle, _) = rtnetlink::new_connection()?;
    // Spawn the `Connection` so that it starts polling the netlink socket in the background.
    tokio::spawn(conn);

    let req = handle.address().get();
    let mut stream = req.execute();

    let mut addrs = vec![];

    while let Some(addr_msg) = stream.try_next().await? {
        // skip non-IPv4/IPv6 addresses
        let valid_addr = match addr_msg.header.family {
            AddressFamily::Inet => options.ipv4,
            AddressFamily::Inet6 => options.ipv6,
            _ => false,
        };
        if !valid_addr {
            continue;
        }

        // take address
        let addr = addr_msg.attributes.iter().find_map(|attr| {
            if let AddressAttribute::Address(addr) = attr {
                Some(addr)
            } else {
                None
            }
        });
        let Some(addr) = addr else {
            continue;
        };

        if addr_msg.header.scope != AddressScope::Universe {
            log::debug!("non-global address {}, skipping", addr);
            continue;
        }

        if let IpAddr::V6(addr_v6) = addr {
            if !is_unicast_global(&addr_v6) {
                log::debug!("non-global ipv6 address {}, skipping", addr);
                continue;
            }
        }

        // cache info
        let cache_info = addr_msg.attributes.iter().find_map(|attr| {
            if let AddressAttribute::CacheInfo(cache_info) = attr {
                Some(cache_info)
            } else {
                None
            }
        });
        if let Some(cache_info) = cache_info {
            // log::info!(
            //     "preferred_lft: {}s, valid_lft: {}",
            //     cache_info.ifa_preferred,
            //     cache_info.ifa_valid
            // );
            if cache_info.ifa_preferred == 0 || cache_info.ifa_valid == 0 {
                log::debug!("address {} is deprecated, skipping", addr);
                continue;
            }
        }
        addrs.push(addr.clone());
    }

    Ok(addrs)
}
