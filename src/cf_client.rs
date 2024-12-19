use std::net::IpAddr;

use anyhow::{Context, Result};

use cloudflare::{
    endpoints::dns::{
        CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, DnsRecord,
        ListDnsRecords, ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
    },
    endpoints::zone::{ListZones, ListZonesParams},
    framework::{
        async_api::Client as CfClient, auth::Credentials, Environment, HttpApiClientConfig,
    },
};

pub struct DDnsClientOption {
    pub ipv4: bool,
    pub ipv6: bool,
    pub ttl: Option<u32>,
    pub max_count: u8,
}

pub struct DDnsClient {
    client: CfClient,
    zone_name: String,
    domain_name: String,
    options: DDnsClientOption,
    zone_id: Option<String>, // zone id cache
    records: Vec<DnsRecord>, // cache existing dns records
    records_dirty: bool,
}

fn ipaddr_to_dnscontent(ip: &IpAddr) -> DnsContent {
    match ip {
        IpAddr::V4(ip_v4) => DnsContent::A {
            content: ip_v4.clone(),
        },
        IpAddr::V6(ip_v6) => DnsContent::AAAA {
            content: ip_v6.clone(),
        },
    }
}

fn dnscontent_to_ipaddr(content: &DnsContent) -> IpAddr {
    match content {
        DnsContent::A { content } => IpAddr::V4(content.clone()),
        DnsContent::AAAA { content } => IpAddr::V6(content.clone()),
        _ => panic!("invalid dns content"),
    }
}

pub async fn get_zone_id(zone_name: String, cf_client: &mut CfClient) -> Result<String> {
    let params = ListZonesParams {
        name: Some(zone_name),
        status: None,
        page: None,
        per_page: None,
        order: None,
        direction: None,
        search_match: None,
    };

    let zones = cf_client
        .request(&ListZones { params })
        .await
        .context("ListZones")?
        .result;
    if let [zone, ..] = zones.as_slice() {
        return Ok(zone.id.clone());
    } else {
        return Err(anyhow::anyhow!("No zone found"));
    }
}

pub async fn get_address_records(
    cf_client: &mut CfClient,
    zone_id: &str,
    domain: &str,
    v4: bool,
    v6: bool,
) -> Result<Vec<DnsRecord>> {
    let records = cf_client
        .request(&ListDnsRecords {
            zone_identifier: zone_id,
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
        .await?
        .result
        .into_iter()
        .filter(|record| match record.content {
            DnsContent::A { .. } => v4,
            DnsContent::AAAA { .. } => v6,
            _ => false,
        })
        .collect();
    Ok(records)
}

// compare records and ips to find records to delete and ips to add
fn diff_records(
    records: Vec<DnsRecord>,
    ips: &Vec<IpAddr>,
) -> (Vec<DnsRecord>, Vec<DnsRecord>, Vec<IpAddr>) {
    let mut records_to_keep: Vec<DnsRecord> = vec![];
    let mut records_to_delete: Vec<DnsRecord> = vec![];
    let mut ips_to_add = ips.clone();

    for record in records {
        let record_ip = match &record.content {
            DnsContent::A { content } => IpAddr::V4(content.clone()),
            DnsContent::AAAA { content } => IpAddr::V6(content.clone()),
            _ => continue,
        };
        if let Some(pos) = ips_to_add.iter().position(|ip| ip == &record_ip) {
            ips_to_add.remove(pos);
            records_to_keep.push(record);
        } else {
            records_to_delete.push(record);
        }
    }

    (records_to_keep, records_to_delete, ips_to_add)
}

impl DDnsClient {
    pub async fn new(
        token: String,
        zone_name: String,
        domain_name: String,
        options: DDnsClientOption,
    ) -> Result<Self> {
        let client = CfClient::new(
            Credentials::UserAuthToken { token: token },
            HttpApiClientConfig::default(),
            Environment::Production,
        )?;

        Ok(DDnsClient {
            client,
            zone_name,
            domain_name,
            options,
            zone_id: None,
            records: vec![],
            records_dirty: true,
        })
    }

    async fn zone_id(&mut self) -> Result<String> {
        if self.zone_id.is_none() {
            self.zone_id = Some(get_zone_id(self.zone_name.clone(), &mut self.client).await?);
        }
        Ok(self.zone_id.clone().unwrap())
    }

    async fn refresh_records(&mut self) -> Result<()> {
        log::info!("refresh dns records");
        let zone_id = self.zone_id().await?;
        let records = get_address_records(
            &mut self.client,
            &zone_id,
            &self.domain_name,
            self.options.ipv4,
            self.options.ipv6,
        )
        .await?;
        log::info!(
            "{} {} have {} records: ",
            self.zone_name,
            self.domain_name,
            records.len()
        );
        for record in &records {
            match record.content {
                DnsContent::A { content } => log::info!("    {}", content),
                DnsContent::AAAA { content } => log::info!("    {}", content),
                _ => (),
            }
        }
        self.records = records;
        Ok(())
    }

    pub async fn update_ips(&mut self, ips: &Vec<IpAddr>) -> Result<()> {
        if self.records_dirty {
            self.refresh_records().await?;
            self.records_dirty = false;
        }

        let (records_to_keep, records_to_delete, mut ips_to_add) =
            diff_records(self.records.split_off(0), ips);

        self.records = records_to_keep;

        // we don't want to exceed the max count
        if self.records.len() >= self.options.max_count as usize {
            ips_to_add.clear();
        } else {
            let max_to_add = self.options.max_count as usize - self.records.len();
            assert!(max_to_add >= 1);
            ips_to_add.truncate(max_to_add);
        }

        if records_to_delete.is_empty() && ips_to_add.is_empty() {
            log::debug!("no record changes");
            return Ok(());
        }

        log::info!(
            "record changes: keep={}, delete={}, add={}",
            self.records.len(),
            records_to_delete.len(),
            ips_to_add.len()
        );

        // mark records dirty incase of failure
        self.records_dirty = true;
        for record in records_to_delete {
            let origin_ip = dnscontent_to_ipaddr(&record.content);
            // update record
            let ip_add = ips_to_add.pop();
            if let Some(ip) = ip_add {
                let updated_record = self
                    .do_update_record(&record.id, &ip)
                    .await
                    .context(format!("update {} to {}", origin_ip, ip))?;
                log::info!("updated {} to {}", origin_ip, ip);
                self.records.push(updated_record);
            } else {
                self.do_delete_record(&record.id)
                    .await
                    .context(format!("delete {}", origin_ip))?;
                log::info!("deleted {}", origin_ip);
            }
        }

        for ip in ips_to_add {
            let new_record = self
                .do_create_record(&ip)
                .await
                .context(format!("add {}", ip))?;
            log::info!("add {} success", ip);
            self.records.push(new_record);
        }

        self.records_dirty = false;
        log::info!("update complete successfully");
        Ok(())
    }

    async fn do_create_record(&mut self, ip: &IpAddr) -> Result<DnsRecord> {
        let zone_id = self.zone_id().await?;
        let create_record_req = CreateDnsRecord {
            zone_identifier: &zone_id,
            params: CreateDnsRecordParams {
                ttl: self.options.ttl,
                priority: None,
                proxied: None,
                name: &self.domain_name,
                content: ipaddr_to_dnscontent(ip),
            },
        };
        let record = self.client.request(&create_record_req).await?.result;
        Ok(record)
    }

    async fn do_update_record(&mut self, record_id: &String, ip: &IpAddr) -> Result<DnsRecord> {
        let zone_id = self.zone_id().await?;
        let update_record_req = UpdateDnsRecord {
            zone_identifier: &zone_id,
            identifier: record_id,
            params: UpdateDnsRecordParams {
                ttl: self.options.ttl,
                proxied: None,
                name: &self.domain_name,
                content: ipaddr_to_dnscontent(ip),
            },
        };
        let record = self.client.request(&update_record_req).await?.result;
        Ok(record)
    }

    async fn do_delete_record(&mut self, record_id: &String) -> Result<()> {
        let zone_id = self.zone_id().await?;
        self.client
            .request(&DeleteDnsRecord {
                zone_identifier: &zone_id,
                identifier: record_id,
            })
            .await?;
        Ok(())
    }
}
