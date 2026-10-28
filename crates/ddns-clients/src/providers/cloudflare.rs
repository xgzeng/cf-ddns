//! [Cloudflare](https://www.cloudflare.com/) DNS provider.

use std::net::IpAddr;

use cloudflare::{
    endpoints::dns::dns::{
        CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, DnsRecord,
        ListDnsRecords, ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
    },
    endpoints::zones::zone::{ListZones, ListZonesParams},
    framework::{
        Environment, auth::Credentials, client::ClientConfig, client::async_api::Client as CfClient,
    },
};

use crate::{AddressRecord, DnsProvider, Error, Result};

/// Manages records of a single Cloudflare zone using an API token.
pub struct CloudflareProvider {
    client: CfClient,
    zone_name: String,
    zone_id: Option<String>, // zone id cache
}

impl CloudflareProvider {
    /// Creates a provider for `zone_name`, authenticating with `api_token`.
    ///
    /// The zone id is looked up lazily on the first request.
    pub fn new(api_token: impl Into<String>, zone_name: impl Into<String>) -> Result<Self> {
        let client = CfClient::new(
            Credentials::UserAuthToken {
                token: api_token.into(),
            },
            ClientConfig::default(),
            Environment::Production,
        )
        .map_err(Error::provider)?;

        Ok(CloudflareProvider {
            client,
            zone_name: zone_name.into(),
            zone_id: None,
        })
    }

    async fn zone_id(&mut self) -> Result<String> {
        if let Some(zone_id) = &self.zone_id {
            return Ok(zone_id.clone());
        }

        let params = ListZonesParams {
            name: Some(self.zone_name.clone()),
            status: None,
            page: None,
            per_page: None,
            order: None,
            direction: None,
            search_match: None,
        };
        let zones = self
            .client
            .request(&ListZones { params })
            .await
            .map_err(Error::provider)?
            .result;
        let Some(zone) = zones.into_iter().next() else {
            return Err(Error::ZoneNotFound(self.zone_name.clone()));
        };
        self.zone_id = Some(zone.id.clone());
        Ok(zone.id)
    }
}

fn ipaddr_to_dnscontent(ip: IpAddr) -> DnsContent {
    match ip {
        IpAddr::V4(content) => DnsContent::A { content },
        IpAddr::V6(content) => DnsContent::AAAA { content },
    }
}

fn to_address_record(record: DnsRecord) -> Option<AddressRecord> {
    let ip = match record.content {
        DnsContent::A { content } => IpAddr::V4(content),
        DnsContent::AAAA { content } => IpAddr::V6(content),
        _ => return None,
    };
    Some(AddressRecord { id: record.id, ip })
}

fn expect_address_record(record: DnsRecord) -> Result<AddressRecord> {
    let id = record.id.clone();
    to_address_record(record)
        .ok_or_else(|| Error::provider(format!("cloudflare returned non-address record {id}")))
}

impl DnsProvider for CloudflareProvider {
    async fn list_address_records(&mut self, domain: &str) -> Result<Vec<AddressRecord>> {
        let zone_id = self.zone_id().await?;
        let records = self
            .client
            .request(&ListDnsRecords {
                zone_identifier: &zone_id,
                params: ListDnsRecordsParams {
                    record_type: None,
                    name: Some(domain.to_string()),
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await
            .map_err(Error::provider)?
            .result
            .into_iter()
            .filter_map(to_address_record)
            .collect();
        Ok(records)
    }

    async fn create_record(
        &mut self,
        domain: &str,
        ip: IpAddr,
        ttl: Option<u32>,
    ) -> Result<AddressRecord> {
        let zone_id = self.zone_id().await?;
        let request = CreateDnsRecord {
            zone_identifier: &zone_id,
            params: CreateDnsRecordParams {
                ttl,
                priority: None,
                proxied: None,
                name: domain,
                content: ipaddr_to_dnscontent(ip),
            },
        };
        log::debug!("request: {request:?}");
        let record = self
            .client
            .request(&request)
            .await
            .map_err(Error::provider)?
            .result;
        expect_address_record(record)
    }

    async fn update_record(
        &mut self,
        domain: &str,
        id: &str,
        ip: IpAddr,
        ttl: Option<u32>,
    ) -> Result<AddressRecord> {
        let zone_id = self.zone_id().await?;
        let request = UpdateDnsRecord {
            zone_identifier: &zone_id,
            identifier: id,
            params: UpdateDnsRecordParams {
                ttl,
                proxied: None,
                name: domain,
                content: ipaddr_to_dnscontent(ip),
            },
        };
        let record = self
            .client
            .request(&request)
            .await
            .map_err(Error::provider)?
            .result;
        expect_address_record(record)
    }

    async fn delete_record(&mut self, id: &str) -> Result<()> {
        let zone_id = self.zone_id().await?;
        self.client
            .request(&DeleteDnsRecord {
                zone_identifier: &zone_id,
                identifier: id,
            })
            .await
            .map_err(Error::provider)?;
        Ok(())
    }
}
