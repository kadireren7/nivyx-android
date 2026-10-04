//! Domain diagnostics: DNS (encrypted vs. plain), HTTPS reachability per strategy, and the
//! current decision, as a JSON document with no secrets.

use crate::split_io::SplitFirstWrite;
use crate::Shared;
use nivyx_core::dns::{self, PoisonVerdict, TYPE_A};
use nivyx_core::strategy::{Family, Key, Source, State, Strategy};
use nivyx_core::tls::{sanitize_host, SplitMode};
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_rustls::TlsConnector;

const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

pub async fn diagnose(sh: &Arc<Shared>, host_in: &str) -> Value {
    let Some(host) = sanitize_host(host_in.trim().as_bytes()) else {
        return json!({ "error": "invalid host name" });
    };
    let cfg = sh.cfg();
    let q = dns::build_query(0x4E56, &host, TYPE_A).expect("validated host");

    // DNS: encrypted resolver vs. the network's plain resolver.
    let t = Instant::now();
    let mut doh_res = json!({ "ok": false });
    let mut doh_addrs: Vec<IpAddr> = vec![];
    for r in &cfg.resolvers {
        match sh.doh.query(r, &q, Duration::from_secs(4)).await {
            Ok(resp) => {
                if let Some(a) = dns::parse_answers(&resp) {
                    doh_addrs = a.addrs.clone();
                    doh_res = json!({
                        "ok": true, "resolver": r.name, "rcode": a.rcode,
                        "addresses": a.addrs.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                        "ms": t.elapsed().as_millis() as u64,
                    });
                    break;
                }
            }
            Err(e) => doh_res = json!({ "ok": false, "resolver": r.name, "error": e.to_string() }),
        }
    }
    let t = Instant::now();
    let (plain_res, plain_addrs) =
        match crate::dns_flow::system_query(sh, &cfg.system_dns, &q).await {
            Some(resp) => match dns::parse_answers(&resp) {
                Some(a) => (
                    json!({ "ok": true, "rcode": a.rcode,
                    "addresses": a.addrs.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                    "ms": t.elapsed().as_millis() as u64 }),
                    a.addrs,
                ),
                None => (
                    json!({ "ok": false, "error": "unparsable response" }),
                    vec![],
                ),
            },
            None => (
                json!({ "ok": false, "error": "no answer from system resolver" }),
                vec![],
            ),
        };
    let verdict = dns::compare_answers(&plain_addrs, &doh_addrs);
    if verdict == PoisonVerdict::Bogus {
        sh.stats
            .dns_poison_suspected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let poisoning = match verdict {
        PoisonVerdict::Clean => "no",
        PoisonVerdict::Bogus => "yes (plain DNS returned a non-routable address)",
        PoisonVerdict::Disjoint => "possible (answers differ; may be CDN variance)",
        PoisonVerdict::Unknown => "unknown",
    };

    // HTTPS: try each strategy against the best address we have.
    let target = doh_addrs
        .iter()
        .chain(plain_addrs.iter())
        .find(|a| a.is_ipv4())
        .copied();
    let https = match target {
        Some(ip) => {
            let direct = probe(sh, ip, &host, None).await;
            let tlsrec = probe(sh, ip, &host, Some(SplitMode::Records)).await;
            let tlsrec_tcp = probe(sh, ip, &host, Some(SplitMode::RecordsTcp)).await;
            json!({ "address": ip.to_string(), "direct": direct, "tlsrec": tlsrec, "tlsrec-tcp": tlsrec_tcp })
        }
        None => json!({ "error": "no address to probe" }),
    };

    let now = sh.now();
    let key = Key::new(
        &sh.salt(),
        cfg.network_id,
        target.map(|i| Family::of(&i)).unwrap_or(Family::V4),
        &host,
    );
    let manual = sh.rules().lookup(&host);
    let d = sh
        .strategy
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .decide(&key, manual, now);
    json!({
        "host": host,
        "dns": { "doh": doh_res, "system": plain_res, "poisoning_suspected": poisoning },
        "https": https,
        "decision": {
            "source": match d.source { Source::Manual => "manual", Source::Learned => "learned", Source::Default => "default" },
            "state": state_name(d.state),
            "ladder": d.ladder.iter().map(|s: &Strategy| s.name()).collect::<Vec<_>>(),
            "ttl_remaining_s": d.ttl_remaining,
        },
    })
}

fn state_name(s: State) -> &'static str {
    match s {
        State::Unknown => "unknown",
        State::DirectGood => "direct-good",
        State::DirectBad => "direct-bad",
        State::TlsRecGood => "tlsrec-good",
        State::TlsRecBad => "tlsrec-bad",
        State::TlsRecTcpGood => "tlsrec-tcp-good",
        State::TlsRecTcpBad => "tlsrec-tcp-bad",
    }
}

/// A full TLS handshake (certificate verified) to `ip:443` with SNI `host`, first flight shaped by `mode`.
async fn probe(sh: &Arc<Shared>, ip: IpAddr, host: &str, mode: Option<SplitMode>) -> Value {
    let started = Instant::now();
    let tcp = match sh
        .connector
        .tcp(SocketAddr::new(ip, 443), PROBE_TIMEOUT)
        .await
    {
        Ok(t) => t,
        Err(e) => return json!({ "ok": false, "stage": "tcp", "error": e.to_string() }),
    };
    let Ok(name) = ServerName::try_from(host.to_string()) else {
        return json!({ "ok": false, "stage": "tls", "error": "bad server name" });
    };
    let connector = TlsConnector::from(sh.tls.clone());
    match tokio::time::timeout(
        PROBE_TIMEOUT,
        connector.connect(name, SplitFirstWrite::new(tcp, mode)),
    )
    .await
    {
        Ok(Ok(_)) => json!({ "ok": true, "ms": started.elapsed().as_millis() as u64 }),
        Ok(Err(e)) => json!({ "ok": false, "stage": "tls", "error": e.to_string() }),
        Err(_) => json!({ "ok": false, "stage": "tls", "error": "timed out" }),
    }
}
