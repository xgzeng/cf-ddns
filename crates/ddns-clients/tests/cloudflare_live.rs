//! Tests against the real Cloudflare API.
//!
//! Set `DDNS_CF_API_TOKEN` (needs `Zone:Read` and `DNS:Edit`) and
//! `DDNS_CF_ZONE` to run them. Records are created on `DDNS_CF_TEST_DOMAIN`,
//! by default a fresh `ddns-clients-test-<unix-seconds>.<zone>`, and removed
//! afterwards. Without the variables the tests print a message and pass.
#![cfg(feature = "cloudflare")]

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use ddns_clients::{
    AddressRecord, CloudflareProvider, DynDnsProvider, Error,
    providers::cloudflare::CloudflareError,
};

struct LiveEnv {
    api_token: String,
    zone: String,
    domain: String,
}

fn live_env() -> Option<LiveEnv> {
    let (Ok(api_token), Ok(zone)) = (
        std::env::var("DDNS_CF_API_TOKEN"),
        std::env::var("DDNS_CF_ZONE"),
    ) else {
        eprintln!("skipping cloudflare live test: set DDNS_CF_API_TOKEN and DDNS_CF_ZONE");
        return None;
    };
    let domain = std::env::var("DDNS_CF_TEST_DOMAIN").unwrap_or_else(|_| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        format!("ddns-clients-test-{}.{zone}", now.as_secs())
    });
    Some(LiveEnv {
        api_token,
        zone,
        domain,
    })
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sorted_ips(records: &[AddressRecord]) -> Vec<IpAddr> {
    let mut ips: Vec<_> = records.iter().map(|r| r.ip).collect();
    ips.sort();
    ips
}

async fn exercise_records(provider: &mut CloudflareProvider, domain: &str) -> Result<(), Error> {
    let records = provider.list_address_records(domain).await?;
    assert!(
        records.is_empty(),
        "{domain} already has records: {records:?}"
    );

    let first = provider
        .create_record(domain, ip("192.0.2.1"), Some(120))
        .await?;
    assert_eq!(first.ip, ip("192.0.2.1"));
    let records = provider.list_address_records(domain).await?;
    assert_eq!(records, vec![first.clone()]);

    let first = provider
        .update_record(domain, &first.id, ip("198.51.100.1"), Some(120))
        .await?;
    assert_eq!(first.ip, ip("198.51.100.1"));

    // A -> AAAA on the same record
    let first = provider
        .update_record(domain, &first.id, ip("2001:db8::1"), None)
        .await?;
    assert_eq!(first.ip, ip("2001:db8::1"));

    let second = provider
        .create_record(domain, ip("192.0.2.2"), None)
        .await?;
    let records = provider.list_address_records(domain).await?;
    assert_eq!(
        sorted_ips(&records),
        vec![ip("192.0.2.2"), ip("2001:db8::1")]
    );

    provider.delete_record(&first.id).await?;
    provider.delete_record(&second.id).await?;
    let records = provider.list_address_records(domain).await?;
    assert!(records.is_empty(), "records left after delete: {records:?}");
    Ok(())
}

#[tokio::test]
async fn record_lifecycle() {
    let Some(env) = live_env() else {
        return;
    };
    eprintln!("using test domain {}", env.domain);
    let new_provider =
        || CloudflareProvider::new(env.api_token.as_str(), env.zone.as_str()).unwrap();

    // run in a task so a failed assertion still reaches the cleanup below
    let mut provider = new_provider();
    let domain = env.domain.clone();
    let result = tokio::spawn(async move { exercise_records(&mut provider, &domain).await }).await;

    match result {
        Ok(Ok(())) => return,
        Ok(Err(err)) => eprintln!("record lifecycle failed: {err:?}"),
        Err(join_err) => eprintln!("record lifecycle panicked: {join_err}"),
    }

    // best-effort cleanup
    let mut provider = new_provider();
    if let Ok(records) = provider.list_address_records(&env.domain).await {
        for record in records {
            let _ = provider.delete_record(&record.id).await;
        }
    }
    panic!("cloudflare record lifecycle test failed, see output above");
}

#[tokio::test]
async fn bad_token_is_reported() {
    if std::env::var_os("DDNS_CF_LIVE").is_none() && std::env::var_os("DDNS_CF_API_TOKEN").is_none()
    {
        eprintln!("skipping cloudflare bad-token test: set DDNS_CF_LIVE=1 (needs network)");
        return;
    }
    let mut provider = CloudflareProvider::new("not-a-valid-token", "example.com").unwrap();
    let err = provider
        .list_address_records("ddns.example.com")
        .await
        .unwrap_err();
    let Error::Provider(err) = err else {
        panic!("unexpected error {err:?}");
    };
    let err = err
        .downcast_ref::<CloudflareError>()
        .expect("a CloudflareError");
    assert!(!(200..300).contains(&err.status), "{err}");
    assert!(!err.errors.is_empty(), "{err}");
}
