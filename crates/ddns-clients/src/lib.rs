//! A multi-provider dynamic DNS client library.
//!
//! - [`detect`] finds this host's public IP addresses.
//! - A [`DnsProvider`] performs record operations against a DNS service,
//!   e.g. [`CloudflareProvider`].
//! - An [`Updater`] reconciles a domain's A/AAAA records with a set of IPs.
//!
//! ```no_run
//! # #[cfg(feature = "cloudflare")]
//! # async fn example() -> ddns_clients::Result<()> {
//! use ddns_clients::{CloudflareProvider, Updater, UpdaterOptions, detect};
//!
//! let provider = CloudflareProvider::new("api-token", "example.com")?;
//! let mut updater = Updater::new(provider, "myhost.example.com", UpdaterOptions::default());
//!
//! let ips = detect::detect_public_ips(&detect::DetectOptions::default()).await;
//! updater.update_ips(&ips).await?;
//! # Ok(())
//! # }
//! ```

pub mod detect;
mod error;
mod provider;
pub mod providers;
mod record;
mod updater;

pub use error::{Error, Result};
pub use provider::DnsProvider;
#[cfg(feature = "cloudflare")]
pub use providers::cloudflare::CloudflareProvider;
pub use record::AddressRecord;
pub use updater::{UpdateSummary, Updater, UpdaterOptions};
