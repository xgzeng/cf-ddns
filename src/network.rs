use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use cloudflare::{
    endpoints::{
        dns::{
            DnsContent, ListDnsRecords, ListDnsRecordsParams, UpdateDnsRecord,
            UpdateDnsRecordParams,
        },
        zone::{ListZones, ListZonesParams},
    },
    framework::async_api::Client as CfClient,
};
use reqwest::Client as ReqwClient;

pub const A_RECORD: DnsContent = DnsContent::A {
    content: Ipv4Addr::UNSPECIFIED,
};
pub const AAAA_RECORD: DnsContent = DnsContent::AAAA {
    content: Ipv6Addr::UNSPECIFIED,
};

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

pub async fn get_zone(domain: String, cf_client: &mut CfClient) -> Result<String> {
    Ok(cf_client
        .request_handle(&ListZones {
            params: ListZonesParams {
                name: Some(domain),
                status: None,
                page: None,
                per_page: None,
                order: None,
                direction: None,
                search_match: None,
            },
        })
        .await?
        .result[0]
        .id
        .clone())
}

pub async fn get_record(
    zone_identifier: &str,
    domain: String,
    r#type: DnsContent,
    cf_client: &mut CfClient,
) -> Result<String> {
    Ok(cf_client
        .request_handle(&ListDnsRecords {
            zone_identifier,
            params: ListDnsRecordsParams {
                record_type: None,
                name: Some(domain),
                page: None,
                per_page: None,
                order: None,
                direction: None,
                search_match: None,
            },
        })
        .await
        .context("Couldn't fetch record")?
        .result
        .iter()
        .find(|record| {
            if std::mem::discriminant(&record.content) == std::mem::discriminant(&r#type) {
                true
            } else {
                false
            }
        })
        .context("No matching record found")?
        .id
        .clone())
}

pub async fn update_record(
    zone_identifier: &str,
    identifier: &str,
    name: &str,
    content: DnsContent,
    cf_client: &mut CfClient,
) -> Result<()> {
    cf_client
        .request_handle(&UpdateDnsRecord {
            zone_identifier,
            identifier,
            params: UpdateDnsRecordParams {
                ttl: None,
                proxied: Some(false),
                name,
                content,
            },
        })
        .await?;
    Ok(())
}
