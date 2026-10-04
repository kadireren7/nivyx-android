//! Leak and long-run behaviour: state must stay bounded and return to baseline.

mod common;
use common::*;
use nivyx_core::dns::{self, TYPE_A};
use nivyx_core::strategy::{Family, Key, Strategy};
use nivyx_core::tls::testutil::client_hello;
use nivyx_engine::dns_flow::resolve;
use nivyx_engine::tcp::handle_tcp;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn status_kb(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0)
}

fn rss_mb() -> f64 {
    status_kb("VmRSS:") as f64 / 1024.0
}

async fn one_flow(sh: &Arc<nivyx_engine::Shared>, sni: &str) {
    let (mut app, engine_side) = tokio::io::duplex(16 * 1024);
    let h = tokio::spawn(handle_tcp(sh.clone(), engine_side, dst(443)));
    app.write_all(&client_hello(sni)).await.unwrap();
    let mut got = [0u8; 9];
    app.read_exact(&mut got).await.unwrap();
    drop(app);
    h.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_thousand_short_tls_connections_leave_no_residue() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let mut cfg = test_config();
    cfg.strategy.max_entries = 256;
    let sh = shared_with(cfg, conn, dummy_tls());

    let run = |from: usize, to: usize| {
        let sh = sh.clone();
        async move {
            // 20 concurrent workers, each flow has a unique host name (worst case for caches).
            let mut tasks = Vec::new();
            for w in 0..20 {
                let sh = sh.clone();
                tasks.push(tokio::spawn(async move {
                    let mut i = from + w;
                    while i < to {
                        // every 50th flow is a blocked host so escalation + learning is exercised too
                        let sni = if i % 50 == 0 {
                            "blocked.example".to_string()
                        } else {
                            format!("h{i}.example.com")
                        };
                        one_flow(&sh, &sni).await;
                        i += 20;
                    }
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }
        }
    };
    run(0, 2_000).await;
    let warm = rss_mb();
    run(2_000, 10_000).await;
    let end = rss_mb();

    let s = sh.stats.snapshot();
    assert_eq!(s.connections_total, 10_000);
    assert_eq!(s.connections_failed, 0);
    assert_eq!(s.flows_active, 0, "every flow released");
    assert!(
        sh.strategy.lock().unwrap().len() <= 256,
        "strategy table bounded: {}",
        sh.strategy.lock().unwrap().len()
    );
    assert!(sh.names.lock().unwrap().len() <= 4096);
    assert!(
        end - warm < 10.0,
        "RSS grew {:.1} MB between 2k and 10k flows ({warm:.1} -> {end:.1})",
        end - warm
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_burst_keeps_caches_bounded() {
    let pki = pki();
    let answers: Vec<(&'static str, Vec<std::net::IpAddr>)> = vec![];
    let doh = fake_doh(&pki, "p", answers).await; // every name -> NXDOMAIN (cached briefly)
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    cfg.dns_cache_entries = 64;
    let sh = shared_with(cfg, TestConnector::new(), pki.client.clone());
    for i in 0..3000 {
        let q = dns::build_query(1, &format!("n{i}.example.net"), TYPE_A).unwrap();
        resolve(&sh, &q).await.unwrap();
    }
    assert!(sh.dns_cache.lock().unwrap().len() <= 64);
    assert!(
        doh.connections.load(SeqCst) <= 3,
        "connection reuse holds under a burst: {}",
        doh.connections.load(SeqCst)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_network_transitions_stay_bounded() {
    let mut cfg = test_config();
    cfg.strategy.max_entries = 128;
    let sh = shared_with(cfg, TestConnector::new(), dummy_tls());
    for round in 0..2_000u64 {
        let net = round % 7 + 1; // Wi-Fi A, mobile, Wi-Fi B, hotspot ... flapping
        sh.network_changed(net, round % 2 == 0, vec![]);
        let key = Key::new(&sh.salt(), net, Family::V4, &format!("h{round}.example"));
        sh.strategy
            .lock()
            .unwrap()
            .report(key, Strategy::Direct, round % 3 == 0, sh.now());
        sh.names
            .lock()
            .unwrap()
            .record("198.51.100.1".parse().unwrap(), "x.example", 60, sh.now());
        assert!(sh.strategy.lock().unwrap().len() <= 128);
    }
    assert!(sh.names.lock().unwrap().len() <= 4096);
    assert_eq!(sh.dns_cache.lock().unwrap().len(), 0);
}

#[test]
fn repeated_engine_start_stop_does_not_leak_threads_or_memory() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let base_threads = status_kb("Threads:");
    let mut after_first = 0.0;
    for i in 0..60 {
        let (tun, _peer) = rt.block_on(async { fake_tun() });
        let stats = Arc::new(nivyx_core::stats::Stats::default());
        let mut e = nivyx_engine::Engine::start_with(
            tun,
            test_config(),
            stats,
            TestConnector::new(),
            dummy_tls(),
        )
        .unwrap();
        e.stop();
        if i == 4 {
            after_first = rss_mb();
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        status_kb("Threads:") <= base_threads + 2,
        "threads {} -> {}",
        base_threads,
        status_kb("Threads:")
    );
    assert!(
        rss_mb() - after_first < 8.0,
        "RSS grew across start/stop cycles"
    );
}

/// Real-time idle test. Run with: NIVYX_IDLE_SECS=1800 cargo test --release -p nivyx-engine --test longrun -- --ignored idle
#[test]
#[ignore]
fn idle_engine_uses_no_cpu_and_does_not_grow() {
    let secs: u64 = std::env::var("NIVYX_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (tun, _peer) = rt.block_on(async { fake_tun() });
    let stats = Arc::new(nivyx_core::stats::Stats::default());
    let mut e = nivyx_engine::Engine::start_with(
        tun,
        test_config(),
        stats,
        TestConnector::new(),
        dummy_tls(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let (rss0, thr0) = (rss_mb(), status_kb("Threads:"));
    let ticks = |_: ()| {
        let s = std::fs::read_to_string("/proc/self/stat").unwrap();
        let f: Vec<&str> = s.rsplit(')').next().unwrap().split_whitespace().collect();
        f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
    };
    let cpu0 = ticks(());
    let mut vol0 = 0u64;
    for t in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let st = std::fs::read_to_string(t.path().join("status")).unwrap_or_default();
        vol0 += st
            .lines()
            .find(|l| l.starts_with("voluntary_ctxt_switches"))
            .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
            .unwrap_or(0);
    }
    std::thread::sleep(Duration::from_secs(secs));
    let mut vol1 = 0u64;
    for t in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let st = std::fs::read_to_string(t.path().join("status")).unwrap_or_default();
        vol1 += st
            .lines()
            .find(|l| l.starts_with("voluntary_ctxt_switches"))
            .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
            .unwrap_or(0);
    }
    let (rss1, thr1, cpu1) = (rss_mb(), status_kb("Threads:"), ticks(()));
    println!("IDLE {secs}s: rss {rss0:.2} -> {rss1:.2} MB, threads {thr0} -> {thr1}, cpu ticks {} (1 tick = 10 ms), wakeups(voluntary ctx switches) {} ({:.3}/s)", cpu1 - cpu0, vol1 - vol0, (vol1 - vol0) as f64 / secs as f64);
    assert!(rss1 - rss0 < 1.0);
    assert_eq!(thr0, thr1);
    assert!(
        cpu1 - cpu0 <= secs.max(10),
        "idle CPU must stay under 0.1% of one core"
    );
    e.stop();
}
