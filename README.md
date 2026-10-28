# DDNS clients

A multi-provider dynamic DNS client library and daemon written in Rust.

| Crate | Path | |
|---|---|---|
| `ddns-clients` | `crates/ddns-clients` | Library: public IP detection, `DnsProvider` trait, record `Updater` |
| `ddnsd` | `crates/ddnsd` | Daemon that periodically syncs a domain's A/AAAA records |

Supported providers: Cloudflare (feature `cloudflare`, on by default).

## Library

```rust
use ddns_clients::{CloudflareProvider, Updater, UpdaterOptions, detect};

let provider = CloudflareProvider::new("api-token", "example.com")?;
let mut updater = Updater::new(provider, "myhost.example.com", UpdaterOptions::default());

let ips = detect::detect_public_ips(&detect::DetectOptions::default()).await;
let summary = updater.update_ips(&ips).await?;
```

To add a provider, implement `ddns_clients::DnsProvider` (list/create/update/delete
address records); `Updater` handles diffing, the record limit and caching.

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
```

Log level is controlled with `RUST_LOG` (default `info`).
