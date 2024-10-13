use ipnetwork::IpNetwork;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use reqwest::Client as ReqwClient;

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
