use std::net::AddrParseError;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The provider has no zone with the given name.
    #[error("zone {0:?} not found")]
    ZoneNotFound(String),

    /// An HTTP request failed.
    #[error("http request failed")]
    Http(#[from] reqwest::Error),

    /// A response did not contain a valid IP address.
    #[error("invalid ip address")]
    InvalidIp(#[from] AddrParseError),

    /// An I/O error, e.g. while opening a netlink socket.
    #[error("i/o error")]
    Io(#[from] std::io::Error),

    /// A netlink request failed.
    #[cfg(target_os = "linux")]
    #[error("netlink request failed")]
    Netlink(#[from] rtnetlink::Error),

    /// A DNS provider reported an error.
    #[error("dns provider error")]
    Provider(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    /// Wraps an arbitrary error from a [`DnsProvider`](crate::DnsProvider) implementation.
    pub fn provider(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Error::Provider(err.into())
    }

    /// Displays this error followed by its chain of sources, `: `-separated.
    pub(crate) fn chain(&self) -> impl std::fmt::Display + '_ {
        Chain(self)
    }
}

struct Chain<'a>(&'a dyn std::error::Error);

impl std::fmt::Display for Chain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(err) = source {
            write!(f, ": {err}")?;
            source = err.source();
        }
        Ok(())
    }
}

/// A `Result` alias using this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
