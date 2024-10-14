use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use reqwest::Client as ReqwClient;

use netlink_packet_route::{
    address::{AddressAttribute, AddressScope},
    AddressFamily,
};

use futures_util::TryStreamExt;

pub async fn query_local_ips(
    reqw_client: &mut ReqwClient,
    v4: bool,
    v6: bool,
) -> Result<Vec<IpAddr>> {
    let mut addrs: Vec<IpAddr> = vec![];

    if v4 {
        let addr = get_current_ipv4(reqw_client).await?;
        addrs.push(IpAddr::V4(addr))
    }

    if v6 {
        let addrs_v6 = get_current_ipv6_local(2);
        addrs.extend(addrs_v6.into_iter().map(|ip| IpAddr::V6(ip)));
    }

    Ok(addrs)
}

pub async fn get_current_ipv4(client: &mut ReqwClient) -> Result<Ipv4Addr> {
    Ok(client
        .get("https://ipv4.icanhazip.com")
        .send()
        .await?
        .text()
        .await?
        .trim()
        .parse()?)
}

pub async fn get_current_ipv6(client: &mut ReqwClient) -> Result<Ipv6Addr> {
    Ok(client
        .get("https://ipv6.icanhazip.com")
        .send()
        .await?
        .text()
        .await?
        .trim()
        .parse()?)
}

fn is_unicast_global(addr: &Ipv6Addr) -> bool {
    !addr.is_multicast() // is_unicast
        && !addr.is_loopback()
        && !((addr.segments()[0] & 0xffc0) == 0xfe80) // !is_unicast_link_local
        && !((addr.segments()[0] & 0xfe00) == 0xfc00) // !is_unique_local
        && !addr.is_unspecified()
        && !((addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8))
}

pub fn get_current_ipv6_local(max_count: u8) -> Vec<Ipv6Addr> {
    pnet_datalink::interfaces()
        .into_iter()
        .flat_map(|net_if| net_if.ips)
        .filter_map(|ip| match ip {
            IpNetwork::V6(addr_v6) if is_unicast_global(&addr_v6.ip()) => {
                Some(addr_v6.ip().clone())
            }
            _ => None,
        })
        .take(max_count as usize)
        .collect()
}

// struct RtnetlinkClient {
//     conn: rtnetlink::Connection,
//     handle: rtnetlink::Handle,
//     receiver: rtnetlink::Receiver,
//     addr: rtnetlink::Address,
// }

// use rtlink to retrieve local ip addresses
pub async fn rtnetlink_get_addresses(ipv4: bool, ipv6: bool) -> Result<Vec<IpAddr>> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    // Spawn the `Connection` so that it starts polling the netlink socket in the background.
    tokio::spawn(conn);

    let req = handle.address().get();
    let mut stream = req.execute();

    let mut addrs = vec![];

    while let Some(addr_msg) = stream.try_next().await? {
        // skip non-IPv4/IPv6 addresses
        let valid_addr = match addr_msg.header.family {
            AddressFamily::Inet => ipv4,
            AddressFamily::Inet6 => ipv6,
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
