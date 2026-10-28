//! DNS providers that manage a domain's address records.
//!
//! A [`DynDnsProvider`] performs the raw record operations against one DNS
//! service:
//!
//! - [`CloudflareProvider`](cloudflare::CloudflareProvider) (feature `cloudflare`).

#[cfg(feature = "cloudflare")]
pub mod cloudflare;

use std::net::IpAddr;

use async_trait::async_trait;

use crate::{AddressRecord, Result};

/// A DNS service that can manage the address records of a domain.
///
/// Implementations only perform the raw record operations; deciding which
/// records to change is left to the caller.
#[async_trait]
pub trait DynDnsProvider: Send {
    /// Lists all A and AAAA records of `domain`.
    async fn list_address_records(&mut self, domain: &str) -> Result<Vec<AddressRecord>>;

    /// Creates an A or AAAA record (depending on `ip`) for `domain`.
    ///
    /// `ttl` of `None` uses the provider's default.
    async fn create_record(
        &mut self,
        domain: &str,
        ip: IpAddr,
        ttl: Option<u32>,
    ) -> Result<AddressRecord>;

    /// Points the existing record `id` of `domain` at `ip`.
    async fn update_record(
        &mut self,
        domain: &str,
        id: &str,
        ip: IpAddr,
        ttl: Option<u32>,
    ) -> Result<AddressRecord>;

    /// Deletes the record `id`.
    async fn delete_record(&mut self, id: &str) -> Result<()>;
}
