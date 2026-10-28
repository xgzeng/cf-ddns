# DDNS clients

A multi-provider dynamic DNS client library and daemon written in Rust.

| Crate | Path | |
|---|---|---|
| `ddns-clients` | `crates/ddns-clients` | Library: `IpResolver` trait and resolvers, `DynDnsProvider` trait and providers |
| `ddnsd` | `crates/ddnsd` | Daemon that periodically syncs a domain's A/AAAA records (owns the record-reconciliation `Updater`) |

DNS providers: Cloudflare (feature `cloudflare`, on by default).

IP resolvers: HTTP echo services (icanhazip, ipify, or custom URLs) and local
interfaces via netlink (Linux). A `Vec` of resolvers falls back in order, per
address family.

## Library

```rust
use ddns_clients::{CloudflareProvider, DynDnsProvider, resolve};

let mut provider = CloudflareProvider::new("api-token", "example.com")?;
let resolvers = resolve::default_resolvers(); // icanhazip, then local interfaces
let ips = resolve::resolve_public_ips(&resolvers, &[resolve::IpFamily::V4]).await;

let records = provider.list_address_records("myhost.example.com").await?;
if records.is_empty() && let Some(ip) = ips.first() {
    provider.create_record("myhost.example.com", *ip, None).await?;
}
```

To add a DNS provider, implement `ddns_clients::providers::DynDnsProvider` (list/create/update/delete
address records); to add an IP source, implement `ddns_clients::IpResolver`.

## Daemon

```sh
cargo run -p ddnsd -- -c /etc/ddnsd.yaml
```

The config file must not be readable by group/others (`chmod 600`).

```yaml
provider:
  type: cloudflare
  api_token: "..."
  zone: example.com
domain: myhost.example.com   # optional, default <hostname>.<zone>
ipv4: true                   # default true
ipv6: true                   # default true
interval: 300                # seconds between checks, default 300
ttl: 600                     # 0 = provider default; default 600
max_records: 2               # max A/AAAA records kept, default 2
resolvers:                   # tried in order per family; default: icanhazip, local
  - type: icanhazip
  - type: ipify
  - type: http               # any service echoing the client IP as plain text
    ipv4_url: https://ipv4.example.net
    ipv6_url: https://ipv6.example.net
  - type: local              # Linux only: global addresses of local interfaces
```

Log level is controlled with `RUST_LOG` (default `info`).

## Testing

```sh
cargo test --workspace
```

The Cloudflare tests in `crates/ddns-clients/tests/cloudflare_live.rs` talk to the
real API and are skipped unless configured:

| Variable | |
|---|---|
| `DDNS_CF_API_TOKEN` | API token with `Zone:Read` and `DNS:Edit` |
| `DDNS_CF_ZONE` | zone to test in, e.g. `example.com` |
| `DDNS_CF_TEST_DOMAIN` | optional; default `ddns-clients-test-<unix-seconds>.<zone>` |
| `DDNS_CF_LIVE=1` | run only the network test that needs no credentials (bad-token handling) |

```sh
DDNS_CF_API_TOKEN=... DDNS_CF_ZONE=example.com \
  cargo test -p ddns-clients --test cloudflare_live -- --nocapture
```

The record test creates, updates and deletes A/AAAA records on the test domain
and cleans up after itself, even on failure.
