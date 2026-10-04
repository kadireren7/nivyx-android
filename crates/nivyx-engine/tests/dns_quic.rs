//! DNS (DoH healthy/unavailable/poisoned), QUIC fallback scoping and network-change behaviour.

mod common;
use common::*;
use nivyx_core::dns::{self, TYPE_A, TYPE_AAAA};
use nivyx_core::strategy::{Family, Key, State, Strategy};
use nivyx_engine::dns_flow::resolve;
use nivyx_engine::udp::{handle_udp, should_reject_quic};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    dns::build_query(0x1234, name, qtype).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_resolves_caches_and_reuses_the_connection() {
    let pki = pki();
    let doh = fake_doh(
        &pki,
        "primary",
        vec![
            ("a.example", vec![ip("192.0.2.1")]),
            ("b.example", vec![ip("192.0.2.2")]),
        ],
    )
    .await;
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());

    let r = resolve(&sh, &query("a.example", TYPE_A)).await.unwrap();
    let a = dns::parse_answers(&r).unwrap();
    assert_eq!(a.addrs, vec![ip("192.0.2.1")]);
    assert_eq!(&r[..2], &[0x12, 0x34], "transaction id is preserved");
    resolve(&sh, &query("a.example", TYPE_A)).await.unwrap();
    resolve(&sh, &query("b.example", TYPE_A)).await.unwrap();
    assert_eq!(
        doh.requests.load(SeqCst),
        2,
        "second a.example answered from cache"
    );
    assert_eq!(
        doh.connections.load(SeqCst),
        1,
        "keep-alive connection reused"
    );
    let s = sh.stats.snapshot();
    assert_eq!((s.dns_queries, s.dns_cache_hits, s.dns_failures), (3, 1, 0));
    assert_eq!(sh.dns_health.consecutive_failures.load(SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_fails_over_between_providers_and_remembers_the_good_one() {
    let pki = pki();
    let bad = fake_doh(&pki, "bad", vec![("x.example", vec![ip("192.0.2.9")])]).await;
    bad.mode.store(DOH_HTTP_503, SeqCst);
    let good = fake_doh(
        &pki,
        "good",
        vec![
            ("x.example", vec![ip("192.0.2.9")]),
            ("y.example", vec![ip("192.0.2.10")]),
        ],
    )
    .await;
    let mut cfg = test_config();
    cfg.resolvers = vec![bad.resolver.clone(), good.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());

    let r = resolve(&sh, &query("x.example", TYPE_A)).await.unwrap();
    assert_eq!(dns::parse_answers(&r).unwrap().addrs, vec![ip("192.0.2.9")]);
    assert_eq!(bad.requests.load(SeqCst), 1);
    let bad_before = bad.requests.load(SeqCst);
    resolve(&sh, &query("y.example", TYPE_A)).await.unwrap();
    assert_eq!(
        bad.requests.load(SeqCst),
        bad_before,
        "preferred resolver is now the healthy one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hanging_resolver_times_out_and_next_provider_answers() {
    let pki = pki();
    let hang = fake_doh(&pki, "hang", vec![]).await;
    hang.mode.store(DOH_HANG, SeqCst);
    let good = fake_doh(&pki, "good", vec![("h.example", vec![ip("192.0.2.5")])]).await;
    let mut cfg = test_config();
    cfg.resolvers = vec![hang.resolver.clone(), good.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());
    let t = std::time::Instant::now();
    let r = resolve(&sh, &query("h.example", TYPE_A)).await.unwrap();
    assert_eq!(dns::parse_answers(&r).unwrap().addrs, vec![ip("192.0.2.5")]);
    assert!(t.elapsed() < Duration::from_secs(7));
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_unavailable_fails_open_to_the_system_resolver() {
    let pki = pki();
    let doh = fake_doh(&pki, "down", vec![]).await;
    doh.mode.store(DOH_HTTP_503, SeqCst);
    let (plain, hits) = fake_plain_dns(vec![("c.example", vec![ip("192.0.2.77")])]).await;
    let conn = TestConnector::new();
    conn.map_udp(SocketAddr::new(ip("127.0.0.53"), 53), plain);
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    cfg.system_dns = vec![ip("127.0.0.53")];
    let sh = shared_with(cfg, conn, pki.client.clone());
    let r = resolve(&sh, &query("c.example", TYPE_A)).await.unwrap();
    assert_eq!(
        dns::parse_answers(&r).unwrap().addrs,
        vec![ip("192.0.2.77")]
    );
    assert_eq!(hits.load(SeqCst), 1);
    assert_eq!(
        sh.stats.snapshot().dns_failures,
        0,
        "answered, so not counted as a failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn total_dns_failure_returns_servfail_and_marks_dns_unhealthy() {
    let pki = pki();
    let doh = fake_doh(&pki, "down", vec![]).await;
    doh.mode.store(DOH_HTTP_503, SeqCst);
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());
    for _ in 0..3 {
        let r = resolve(&sh, &query("nope.example", TYPE_A)).await.unwrap();
        assert_eq!(dns::rcode(&r), Some(2));
    }
    assert_eq!(sh.stats.snapshot().dns_failures, 3);
    assert!(sh.dns_health.consecutive_failures.load(SeqCst) >= 3);
    // Recovery: DoH comes back, health resets.
    doh.mode.store(DOH_HEALTHY, SeqCst);
}

#[tokio::test(flavor = "multi_thread")]
async fn local_names_never_reach_the_public_resolver() {
    let pki = pki();
    let doh = fake_doh(&pki, "p", vec![]).await;
    let (plain, hits) = fake_plain_dns(vec![
        ("printer.local", vec![ip("192.168.1.50")]),
        ("nas", vec![ip("192.168.1.9")]),
    ])
    .await;
    let conn = TestConnector::new();
    conn.map_udp(SocketAddr::new(ip("127.0.0.53"), 53), plain);
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    cfg.system_dns = vec![ip("127.0.0.53")];
    let sh = shared_with(cfg, conn, pki.client.clone());
    for n in ["printer.local", "nas"] {
        let r = resolve(&sh, &query(n, TYPE_A)).await.unwrap();
        assert_eq!(dns::parse_answers(&r).unwrap().addrs.len(), 1, "{n}");
    }
    assert_eq!(doh.requests.load(SeqCst), 0);
    assert_eq!(hits.load(SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn aaaa_is_answered_empty_while_ipv6_is_not_tunneled() {
    let pki = pki();
    let doh = fake_doh(&pki, "p", vec![("v6.example", vec![ip("192.0.2.1")])]).await;
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());
    let r = resolve(&sh, &query("v6.example", TYPE_AAAA)).await.unwrap();
    let a = dns::parse_answers(&r).unwrap();
    assert_eq!((a.rcode, a.answer_count), (0, 0));
    assert_eq!(doh.requests.load(SeqCst), 0);
    // IPv6 becomes available on the network: AAAA is now forwarded.
    sh.network_changed(1, true, vec![]);
    let _ = resolve(&sh, &query("v6.example", TYPE_AAAA)).await.unwrap();
    assert_eq!(doh.requests.load(SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn diagnostics_flag_poisoned_plain_dns_and_report_https_per_strategy() {
    let pki = pki();
    // "DoH" says localhost = 203.0.113.5 (routable; the connector remaps it to a local TLS server);
    // the network's plain DNS lies with 0.0.0.0.
    let doh = fake_doh(&pki, "p", vec![("localhost", vec![ip("203.0.113.5")])]).await;
    let (plain, _) = fake_plain_dns(vec![("localhost", vec![ip("0.0.0.0")])]).await;
    let tls_server = fake_doh(&pki, "tls-target", vec![]).await; // any TLS server with a cert valid for "localhost"
    let conn = TestConnector::new();
    conn.map_udp(SocketAddr::new(ip("127.0.0.53"), 53), plain);
    let tls_port: u16 = tls_server
        .resolver
        .url
        .split(':')
        .nth(2)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    conn.map_tcp(
        "203.0.113.5:443".parse().unwrap(),
        format!("127.0.0.1:{tls_port}").parse().unwrap(),
    );
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    cfg.system_dns = vec![ip("127.0.0.53")];
    let sh = shared_with(cfg, conn, pki.client.clone());

    let v = nivyx_engine::diag::diagnose(&sh, "localhost").await;
    assert!(
        v["dns"]["poisoning_suspected"]
            .as_str()
            .unwrap()
            .starts_with("yes"),
        "{v}"
    );
    assert_eq!(v["dns"]["doh"]["ok"], true);
    for s in ["direct", "tlsrec", "tlsrec-tcp"] {
        assert_eq!(v["https"][s]["ok"], true, "{s}: {v}");
    }
    assert_eq!(v["decision"]["source"], "default");
    assert!(sh.stats.snapshot().dns_poison_suspected >= 1);
    // Invalid input is rejected without any network activity.
    assert!(nivyx_engine::diag::diagnose(&sh, "bad host!").await["error"].is_string());
}

fn quic_initial() -> Vec<u8> {
    let mut p = vec![0x55u8; 1252];
    p[0] = 0xC3;
    p[1..5].copy_from_slice(&1u32.to_be_bytes());
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_is_rejected_only_for_destinations_of_bypass_hosts_and_only_while_fresh() {
    let pki = pki();
    let doh = fake_doh(
        &pki,
        "p",
        vec![
            ("blocked.example", vec![ip("198.51.100.7")]),
            ("fine.example", vec![ip("198.51.100.8")]),
        ],
    )
    .await;
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());
    resolve(&sh, &query("blocked.example", TYPE_A))
        .await
        .unwrap();
    resolve(&sh, &query("fine.example", TYPE_A)).await.unwrap();
    let k = Key::new(&sh.salt(), 1, Family::V4, "blocked.example");
    {
        let mut e = sh.strategy.lock().unwrap();
        e.report(k, Strategy::Direct, false, sh.now());
        e.report(k, Strategy::TlsRec, true, sh.now());
    }
    let d = |a: &str| SocketAddr::new(ip(a), 443);
    assert!(should_reject_quic(&sh, &d("198.51.100.7"), &quic_initial()));
    assert!(
        !should_reject_quic(&sh, &d("198.51.100.8"), &quic_initial()),
        "unrelated host untouched"
    );
    assert!(
        !should_reject_quic(&sh, &d("198.51.100.99"), &quic_initial()),
        "unknown destination untouched"
    );
    assert!(
        !should_reject_quic(&sh, &d("198.51.100.7"), b"not quic"),
        "non-QUIC datagram untouched"
    );
    assert!(
        !should_reject_quic(
            &sh,
            &SocketAddr::new(ip("198.51.100.7"), 8443),
            &quic_initial()
        ),
        "only :443"
    );
    // Mapping goes stale after at most 5 minutes: no stale-CDN-address blocking.
    sh.clock_offset.fetch_add(301, SeqCst);
    assert!(!should_reject_quic(
        &sh,
        &d("198.51.100.7"),
        &quic_initial()
    ));
    // Feature switch.
    sh.clock_offset.store(0, SeqCst);
    let mut c = (*sh.cfg()).clone();
    c.quic_fallback = false;
    sh.set_config(c);
    assert!(!should_reject_quic(
        &sh,
        &d("198.51.100.7"),
        &quic_initial()
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_flow_relays_normally_and_drops_rejected_quic() {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, p)) = echo.recv_from(&mut b).await {
            let _ = echo.send_to(&b[..n], p).await;
        }
    });
    let conn = TestConnector::new();
    let target = SocketAddr::new(ip("198.51.100.20"), 4000);
    conn.map_udp(target, echo_addr);
    let sh = shared_with(test_config(), conn.clone(), dummy_tls());
    let (mut app, engine_side) = tokio::io::duplex(8192);
    tokio::spawn(handle_udp(sh.clone(), engine_side, target));
    app.write_all(b"hello udp").await.unwrap();
    let mut got = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(3), app.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"hello udp");

    // A rejected QUIC flow is closed without ever creating an upstream socket.
    let q_dst = SocketAddr::new(ip("198.51.100.7"), 443);
    sh.names
        .lock()
        .unwrap()
        .record(q_dst.ip(), "blocked.example", 60, sh.now());
    let k = Key::new(&sh.salt(), 1, Family::V4, "blocked.example");
    sh.strategy
        .lock()
        .unwrap()
        .report(k, Strategy::Direct, false, sh.now());
    let (mut app2, engine_side2) = tokio::io::duplex(8192);
    let h = tokio::spawn(handle_udp(sh.clone(), engine_side2, q_dst));
    app2.write_all(&quic_initial()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), h)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sh.stats.snapshot().quic_rejected, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn network_change_rescopes_learned_decisions_and_drops_dns_state() {
    let pki = pki();
    let doh = fake_doh(&pki, "p", vec![("n.example", vec![ip("192.0.2.3")])]).await;
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());
    resolve(&sh, &query("n.example", TYPE_A)).await.unwrap();

    let home = Key::new(&sh.salt(), 1, Family::V4, "blocked.example");
    sh.strategy
        .lock()
        .unwrap()
        .report(home, Strategy::Direct, false, sh.now());

    sh.network_changed(2, false, vec![ip("10.0.0.1")]);
    let cfg2 = sh.cfg();
    assert_eq!(cfg2.network_id, 2);
    assert_eq!(cfg2.system_dns, vec![ip("10.0.0.1")]);
    let other = Key::new(&sh.salt(), cfg2.network_id, Family::V4, "blocked.example");
    assert_eq!(
        sh.strategy
            .lock()
            .unwrap()
            .decide(&other, None, sh.now())
            .state,
        State::Unknown,
        "other network starts clean"
    );
    // DNS cache was flushed: the next query hits the resolver again.
    resolve(&sh, &query("n.example", TYPE_A)).await.unwrap();
    assert_eq!(doh.requests.load(SeqCst), 2);
    // Returning to the original network restores its (still valid) knowledge.
    sh.network_changed(1, false, vec![]);
    assert_eq!(
        sh.strategy
            .lock()
            .unwrap()
            .decide(&home, None, sh.now())
            .state,
        State::DirectBad
    );
    // Learned data can be exported/imported across restarts without storing host names.
    assert!(!sh
        .strategy
        .lock()
        .unwrap()
        .export(sh.now(), 10)
        .iter()
        .any(|_| false));
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_dns_framing_is_supported() {
    let pki = pki();
    let doh = fake_doh(&pki, "p", vec![("t.example", vec![ip("192.0.2.4")])]).await;
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());
    let (mut app, engine_side) = tokio::io::duplex(8192);
    tokio::spawn(nivyx_engine::dns_flow::tcp_dns(sh, engine_side));
    let q = query("t.example", TYPE_A);
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    app.write_all(&framed).await.unwrap();
    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut len))
        .await
        .unwrap()
        .unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    app.read_exact(&mut body).await.unwrap();
    assert_eq!(
        dns::parse_answers(&body).unwrap().addrs,
        vec![ip("192.0.2.4")]
    );
}
