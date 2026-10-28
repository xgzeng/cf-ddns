//! A multi-provider dynamic DNS client library.
//!
//! - An [`IpResolver`] finds this host's public IP addresses, e.g.
//!   [`HttpResolver`](resolve::HttpResolver); see [`resolve`].
//! - A [`DnsProvider`] performs address record operations against a DNS
//!   service, e.g. [`CloudflareProvider`].
//!
//! ```no_run
//! # #[cfg(feature = "cloudflare")]
//! # async fn example() -> ddns_clients::Result<()> {
//! use ddns_clients::{CloudflareProvider, DnsProvider, resolve};
//!
//! let mut provider = CloudflareProvider::new("api-token", "example.com")?;
//! let resolvers = resolve::default_resolvers();
//! let ips = resolve::resolve_public_ips(&resolvers, &[resolve::IpFamily::V4]).await;
//!
//! let records = provider.list_address_records("myhost.example.com").await?;
//! if records.is_empty() && let Some(ip) = ips.first() {
//!     provider.create_record("myhost.example.com", *ip, None).await?;
//! }
//! # Ok(())
//! # }
//! ```

mod error;
mod provider;
pub mod providers;
mod record;
pub mod resolve;

pub use error::{Error, Result};
pub use provider::DnsProvider;
#[cfg(feature = "cloudflare")]
pub use providers::cloudflare::CloudflareProvider;
pub use record::AddressRecord;
pub use resolve::IpResolver;
