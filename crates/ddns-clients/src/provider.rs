use std::net::IpAddr;

use crate::{AddressRecord, Result};

/// A DNS service that can manage the address records of a domain.
///
/// Implementations only perform the raw record operations; deciding which
/// records to change is left to the caller.
pub trait DnsProvider {
    /// Lists all A and AAAA records of `domain`.
    fn list_address_records(
        &mut self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<AddressRecord>>> + Send;

    /// Creates an A or AAAA record (depending on `ip`) for `domain`.
    ///
    /// `ttl` of `None` uses the provider's default.
    fn create_record(
        &mut self,
        domain: &str,
        ip: IpAddr,
        ttl: Option<u32>,
    ) -> impl Future<Output = Result<AddressRecord>> + Send;

    /// Points the existing record `id` of `domain` at `ip`.
    fn update_record(
        &mut self,
        domain: &str,
        id: &str,
        ip: IpAddr,
        ttl: Option<u32>,
    ) -> impl Future<Output = Result<AddressRecord>> + Send;

    /// Deletes the record `id`.
    fn delete_record(&mut self, id: &str) -> impl Future<Output = Result<()>> + Send;
}
