//! Detection of this host's public IP addresses.

use std::net::{IpAddr, Ipv6Addr};

use crate::Result;

#[cfg(target_os = "linux")]
use futures_util::TryStreamExt;
#[cfg(target_os = "linux")]
use netlink_packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressScope},
};

/// Which address families to detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectOptions {
    /// Detect IPv4 addresses.
    pub ipv4: bool,
    /// Detect IPv6 addresses.
    pub ipv6: bool,
}

impl Default for DetectOptions {
    fn default() -> Self {
        DetectOptions {
            ipv4: true,
            ipv6: true,
        }
    }
}

/// Detects public addresses, trying an online service first and falling back
/// to the addresses of local interfaces (Linux only).
///
/// Failures are logged; an empty list means nothing could be detected.
pub async fn detect_public_ips(options: &DetectOptions) -> Vec<IpAddr> {
    match detect_online(options).await {
        Ok(addrs) => return addrs,
        Err(err) => log::warn!("detect public ip online failed: {}", err.chain()),
    }

    #[cfg(target_os = "linux")]
    match detect_local(options).await {
        Ok(addrs) => return addrs,
        Err(err) => log::warn!(
            "detect public ip from local interfaces failed: {}",
            err.chain()
        ),
    }

    vec![]
}

/// Detects public addresses by querying <https://icanhazip.com>.
pub async fn detect_online(options: &DetectOptions) -> Result<Vec<IpAddr>> {
    let client = reqwest::Client::new();

    let mut urls = vec![];
    if options.ipv4 {
        urls.push("https://ipv4.icanhazip.com");
    }
    if options.ipv6 {
        urls.push("https://ipv6.icanhazip.com");
    }

    let mut addrs = vec![];
    for url in urls {
        let addr: IpAddr = client
            .get(url)
            .send()
            .await?
            .error_for_status()?
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
        && (addr.segments()[0] & 0xffc0) != 0xfe80 // !is_unicast_link_local
        && (addr.segments()[0] & 0xfe00) != 0xfc00 // !is_unique_local
        && !addr.is_unspecified()
        && !((addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)) // !documentation
}

/// Detects public addresses assigned to local interfaces via netlink.
///
/// Skips non-global and deprecated addresses. Must be called from within a
/// Tokio runtime.
#[cfg(target_os = "linux")]
pub async fn detect_local(options: &DetectOptions) -> Result<Vec<IpAddr>> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    // Spawn the `Connection` so that it starts polling the netlink socket in the background.
    tokio::spawn(conn);

    let mut stream = handle.address().get().execute();
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

        let addr = addr_msg.attributes.iter().find_map(|attr| match attr {
            AddressAttribute::Address(addr) => Some(*addr),
            _ => None,
        });
        let Some(addr) = addr else {
            continue;
        };

        if addr_msg.header.scope != AddressScope::Universe {
            log::debug!("non-global address {addr}, skipping");
            continue;
        }

        if let IpAddr::V6(addr_v6) = addr
            && !is_unicast_global(&addr_v6)
        {
            log::debug!("non-global ipv6 address {addr}, skipping");
            continue;
        }

        let cache_info = addr_msg.attributes.iter().find_map(|attr| match attr {
            AddressAttribute::CacheInfo(cache_info) => Some(cache_info),
            _ => None,
        });
        if let Some(cache_info) = cache_info
            && (cache_info.ifa_preferred == 0 || cache_info.ifa_valid == 0)
        {
            log::debug!("address {addr} is deprecated, skipping");
            continue;
        }

        addrs.push(addr);
    }

    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicast_global() {
        let global = |s: &str| is_unicast_global(&s.parse().unwrap());
        assert!(global("2606:4700::1111"));
        assert!(global("2408:8207:1:2::3"));
        assert!(!global("::1"));
        assert!(!global("::"));
        assert!(!global("fe80::1"));
        assert!(!global("fd00::1"));
        assert!(!global("fc12::1"));
        assert!(!global("ff02::1"));
        assert!(!global("2001:db8::1"));
    }
}
