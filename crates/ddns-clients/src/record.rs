use std::net::IpAddr;

/// An address (A or AAAA) record as stored by a DNS provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRecord {
    /// Provider-specific record identifier.
    pub id: String,
    /// The address the record points to; its family decides A vs. AAAA.
    pub ip: IpAddr,
}
