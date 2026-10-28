use std::net::IpAddr;

use ddns_clients::{AddressRecord, DynDnsProvider, Result};

/// Settings for an [`Updater`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdaterOptions {
    /// Manage A records.
    pub ipv4: bool,
    /// Manage AAAA records.
    pub ipv6: bool,
    /// TTL for created/updated records; `None` uses the provider's default.
    pub ttl: Option<u32>,
    /// Maximum number of address records kept for the domain.
    pub max_records: usize,
}

impl Default for UpdaterOptions {
    fn default() -> Self {
        UpdaterOptions {
            ipv4: true,
            ipv6: true,
            ttl: None,
            max_records: 2,
        }
    }
}

/// What a call to [`Updater::update_ips`] changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpdateSummary {
    /// Records that already matched and were left alone.
    pub kept: usize,
    /// Stale records re-pointed at a new address.
    pub updated: usize,
    /// Stale records removed.
    pub deleted: usize,
    /// Records newly created.
    pub created: usize,
}

impl UpdateSummary {
    /// Returns `true` if no record was changed.
    pub fn is_unchanged(&self) -> bool {
        self.updated == 0 && self.deleted == 0 && self.created == 0
    }
}

/// Keeps the address records of one domain in sync with a set of IPs.
///
/// Records are cached between calls and only re-fetched from the provider
/// after a failed update.
pub struct Updater<P> {
    provider: P,
    domain: String,
    options: UpdaterOptions,
    records: Vec<AddressRecord>, // cache existing dns records
    records_dirty: bool,
}

impl<P: DynDnsProvider> Updater<P> {
    /// Creates an updater managing `domain` through `provider`.
    pub fn new(provider: P, domain: impl Into<String>, options: UpdaterOptions) -> Self {
        Updater {
            provider,
            domain: domain.into(),
            options,
            records: vec![],
            records_dirty: true,
        }
    }

    fn is_enabled(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.options.ipv4,
            IpAddr::V6(_) => self.options.ipv6,
        }
    }

    async fn refresh_records(&mut self) -> Result<()> {
        log::info!("refresh dns records");
        let mut records = self.provider.list_address_records(&self.domain).await?;
        records.retain(|record| self.is_enabled(&record.ip));
        log::info!("{} have {} records: ", self.domain, records.len());
        for record in &records {
            log::info!("    {}", record.ip);
        }
        self.records = records;
        Ok(())
    }

    /// Makes the domain's records point at `ips`.
    ///
    /// Addresses of disabled families are ignored. Stale records are updated
    /// in place where possible, surplus ones deleted, and new ones created up
    /// to [`UpdaterOptions::max_records`].
    pub async fn update_ips(&mut self, ips: &[IpAddr]) -> Result<UpdateSummary> {
        if self.records_dirty {
            self.refresh_records().await?;
            self.records_dirty = false;
        }

        let ips: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| self.is_enabled(ip))
            .collect();
        let (records_to_keep, records_to_delete, mut ips_to_add) =
            diff_records(std::mem::take(&mut self.records), &ips);

        self.records = records_to_keep;

        // we don't want to exceed the max count
        ips_to_add.truncate(self.options.max_records.saturating_sub(self.records.len()));

        let mut summary = UpdateSummary {
            kept: self.records.len(),
            ..Default::default()
        };

        if records_to_delete.is_empty() && ips_to_add.is_empty() {
            log::debug!("no record changes");
            return Ok(summary);
        }

        log::info!(
            "record changes: keep={}, delete={}, add={}",
            self.records.len(),
            records_to_delete.len(),
            ips_to_add.len()
        );

        // mark records dirty in case of failure
        self.records_dirty = true;
        for record in records_to_delete {
            if let Some(ip) = ips_to_add.pop() {
                let updated = self
                    .provider
                    .update_record(&self.domain, &record.id, ip, self.options.ttl)
                    .await?;
                log::info!("updated {} to {}", record.ip, ip);
                self.records.push(updated);
                summary.updated += 1;
            } else {
                self.provider.delete_record(&record.id).await?;
                log::info!("deleted {}", record.ip);
                summary.deleted += 1;
            }
        }

        for ip in ips_to_add {
            let created = self
                .provider
                .create_record(&self.domain, ip, self.options.ttl)
                .await?;
            log::info!("add {ip} success");
            self.records.push(created);
            summary.created += 1;
        }

        self.records_dirty = false;
        Ok(summary)
    }
}

/// Splits `records` into those matching one of `ips` (kept) and the rest
/// (to delete), and returns the `ips` not covered by any record (to add).
fn diff_records(
    records: Vec<AddressRecord>,
    ips: &[IpAddr],
) -> (Vec<AddressRecord>, Vec<AddressRecord>, Vec<IpAddr>) {
    let mut records_to_keep = vec![];
    let mut records_to_delete = vec![];
    let mut ips_to_add = ips.to_vec();

    for record in records {
        if let Some(pos) = ips_to_add.iter().position(|ip| ip == &record.ip) {
            ips_to_add.remove(pos);
            records_to_keep.push(record);
        } else {
            records_to_delete.push(record);
        }
    }

    (records_to_keep, records_to_delete, ips_to_add)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ddns_clients::Error;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rec(id: &str, addr: &str) -> AddressRecord {
        AddressRecord {
            id: id.to_string(),
            ip: ip(addr),
        }
    }

    #[derive(Default)]
    struct MockProvider {
        records: Vec<AddressRecord>,
        next_id: usize,
        fail_next: bool,
        list_calls: usize,
    }

    impl MockProvider {
        fn with(records: Vec<AddressRecord>) -> Self {
            MockProvider {
                records,
                ..Default::default()
            }
        }

        fn check_fail(&mut self) -> Result<()> {
            if std::mem::take(&mut self.fail_next) {
                return Err(Error::provider("injected failure"));
            }
            Ok(())
        }

        fn ips(&self) -> Vec<IpAddr> {
            let mut ips: Vec<_> = self.records.iter().map(|r| r.ip).collect();
            ips.sort();
            ips
        }
    }

    #[async_trait]
    impl DynDnsProvider for MockProvider {
        async fn list_address_records(&mut self, _domain: &str) -> Result<Vec<AddressRecord>> {
            self.list_calls += 1;
            self.check_fail()?;
            Ok(self.records.clone())
        }

        async fn create_record(
            &mut self,
            _domain: &str,
            ip: IpAddr,
            _ttl: Option<u32>,
        ) -> Result<AddressRecord> {
            self.check_fail()?;
            self.next_id += 1;
            let record = AddressRecord {
                id: format!("new{}", self.next_id),
                ip,
            };
            self.records.push(record.clone());
            Ok(record)
        }

        async fn update_record(
            &mut self,
            _domain: &str,
            id: &str,
            ip: IpAddr,
            _ttl: Option<u32>,
        ) -> Result<AddressRecord> {
            self.check_fail()?;
            let record = self.records.iter_mut().find(|r| r.id == id).unwrap();
            record.ip = ip;
            Ok(record.clone())
        }

        async fn delete_record(&mut self, id: &str) -> Result<()> {
            self.check_fail()?;
            self.records.retain(|r| r.id != id);
            Ok(())
        }
    }

    fn updater(provider: MockProvider, options: UpdaterOptions) -> Updater<MockProvider> {
        Updater::new(provider, "host.example.com", options)
    }

    #[test]
    fn diff() {
        let records = vec![rec("a", "1.1.1.1"), rec("b", "2.2.2.2")];
        let (keep, delete, add) = diff_records(records, &[ip("2.2.2.2"), ip("3.3.3.3")]);
        assert_eq!(keep, vec![rec("b", "2.2.2.2")]);
        assert_eq!(delete, vec![rec("a", "1.1.1.1")]);
        assert_eq!(add, vec![ip("3.3.3.3")]);
    }

    #[test]
    fn diff_duplicates() {
        let records = vec![rec("a", "1.1.1.1"), rec("b", "1.1.1.1")];
        let (keep, delete, add) = diff_records(records, &[ip("1.1.1.1")]);
        assert_eq!(keep, vec![rec("a", "1.1.1.1")]);
        assert_eq!(delete, vec![rec("b", "1.1.1.1")]);
        assert!(add.is_empty());
    }

    #[tokio::test]
    async fn unchanged() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1")]);
        let mut u = updater(provider, UpdaterOptions::default());
        let summary = u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert!(summary.is_unchanged());
        assert_eq!(summary.kept, 1);
    }

    #[tokio::test]
    async fn creates_missing() {
        let mut u = updater(MockProvider::default(), UpdaterOptions::default());
        let summary = u
            .update_ips(&[ip("1.1.1.1"), ip("2001:4860::1")])
            .await
            .unwrap();
        assert_eq!(summary.created, 2);
        assert_eq!(u.provider.ips(), vec![ip("1.1.1.1"), ip("2001:4860::1")]);
        assert_eq!(u.records.len(), 2);
    }

    #[tokio::test]
    async fn replaces_via_update() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1")]);
        let mut u = updater(provider, UpdaterOptions::default());
        let summary = u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(
            summary,
            UpdateSummary {
                updated: 1,
                ..Default::default()
            }
        );
        assert_eq!(u.provider.records, vec![rec("a", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn deletes_surplus() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1"), rec("b", "2.2.2.2")]);
        let mut u = updater(provider, UpdaterOptions::default());
        let summary = u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(summary.deleted, 1);
        assert_eq!(u.provider.records, vec![rec("b", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn caps_at_max_records() {
        let options = UpdaterOptions {
            max_records: 1,
            ..Default::default()
        };
        let mut u = updater(MockProvider::default(), options);
        let summary = u.update_ips(&[ip("1.1.1.1"), ip("2.2.2.2")]).await.unwrap();
        assert_eq!(summary.created, 1);
        assert_eq!(u.provider.records.len(), 1);
    }

    #[tokio::test]
    async fn ignores_disabled_family() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1")]);
        let options = UpdaterOptions {
            ipv4: false,
            ..Default::default()
        };
        let mut u = updater(provider, options);
        let summary = u
            .update_ips(&[ip("2.2.2.2"), ip("2001:4860::1")])
            .await
            .unwrap();
        assert_eq!(
            summary,
            UpdateSummary {
                created: 1,
                ..Default::default()
            }
        );
        assert_eq!(u.provider.ips(), vec![ip("1.1.1.1"), ip("2001:4860::1")]);
    }

    #[tokio::test]
    async fn refreshes_after_failure() {
        let mut u = updater(MockProvider::default(), UpdaterOptions::default());
        u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(u.provider.list_calls, 1);

        // cached records are reused while updates succeed
        u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(u.provider.list_calls, 1);

        u.provider.fail_next = true;
        u.update_ips(&[ip("2.2.2.2")]).await.unwrap_err();

        u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(u.provider.list_calls, 2);
        assert_eq!(u.provider.records, vec![rec("new1", "2.2.2.2")]);
    }
}
