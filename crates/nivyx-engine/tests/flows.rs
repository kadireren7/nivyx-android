//! TCP/TLS flow behaviour against a fake DPI middlebox.

mod common;
use common::*;
use nivyx_core::strategy::{Family, Key, State, Strategy};
use nivyx_core::tls::testutil::{client_hello, client_hello_handshake, one_record};
use nivyx_engine::tcp::handle_tcp;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn key_for(sh: &nivyx_engine::Shared, host: &str) -> Key {
    Key::new(&sh.salt(), 1, Family::V4, host)
}

fn state(sh: &nivyx_engine::Shared, host: &str) -> State {
    sh.strategy
        .lock()
        .unwrap()
        .decide(&key_for(sh, host), None, sh.now())
        .state
}

/// Spawn the flow handler and return the app side of a duplex pipe.
fn open_flow(sh: &std::sync::Arc<nivyx_engine::Shared>, port: u16) -> tokio::io::DuplexStream {
    let (app, engine_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(handle_tcp(sh.clone(), engine_side, dst(port)));
    app
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_tls_works_and_is_learned_as_direct_good() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());

    let mut app = open_flow(&sh, 443);
    run_app(&mut app, &client_hello("fine.example"), 1)
        .await
        .unwrap();

    assert_eq!(state(&sh, "fine.example"), State::DirectGood);
    let s = sh.stats.snapshot();
    assert_eq!(
        (s.connections_direct, s.connections_bypassed, s.escalations),
        (1, 0, 0)
    );
    assert_eq!(dpi.blocked.load(SeqCst), 0);
    assert_eq!(dpi.valid_hellos.load(SeqCst), 1);
    assert_eq!(
        dpi.split_hellos.load(SeqCst),
        0,
        "ordinary hosts must not be fragmented"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_reset_escalates_transparently_to_tls_record_split() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn.clone(), dummy_tls());

    let mut app = open_flow(&sh, 443);
    run_app(&mut app, &client_hello("blocked.example"), 1)
        .await
        .unwrap();

    assert_eq!(
        dpi.blocked.load(SeqCst),
        1,
        "direct attempt was reset by the middlebox"
    );
    assert_eq!(
        dpi.split_hellos.load(SeqCst),
        1,
        "retry arrived as two TLS records"
    );
    assert_eq!(
        dpi.valid_hellos.load(SeqCst),
        1,
        "server still saw a well-formed ClientHello"
    );
    assert_eq!(state(&sh, "blocked.example"), State::TlsRecGood);
    let s = sh.stats.snapshot();
    assert_eq!(
        (s.connections_bypassed, s.escalations, s.strategy_tlsrec),
        (1, 1, 1)
    );

    // Second connection: learned, so it goes straight to tlsrec — the middlebox is not hit again.
    let before = dpi.blocked.load(SeqCst);
    let mut app2 = open_flow(&sh, 443);
    run_app(&mut app2, &client_hello("blocked.example"), 1)
        .await
        .unwrap();
    assert_eq!(dpi.blocked.load(SeqCst), before);
    assert_eq!(sh.stats.snapshot().escalations, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn blackholed_direct_times_out_then_tlsrec_succeeds() {
    let dpi = dpi_server("blocked.example", Block::Blackhole).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let mut app = open_flow(&sh, 443);
    let t = std::time::Instant::now();
    run_app(&mut app, &client_hello("blocked.example"), 1)
        .await
        .unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(450),
        "waited for the first-byte timeout"
    );
    assert_eq!(state(&sh, "blocked.example"), State::TlsRecGood);
}

#[tokio::test(flavor = "multi_thread")]
async fn tlsrec_tcp_is_used_when_enabled_and_needed() {
    // A middlebox that also defeats plain record splitting would need tlsrec-tcp; here we only
    // verify the optional strategy is part of the ladder when enabled and is applied as 2 writes.
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let mut cfg = test_config();
    cfg.strategy.allow_tlsrec_tcp = true;
    let sh = shared_with(cfg, conn, dummy_tls());
    // Manual rule forces the optional strategy first.
    let mut c = (*sh.cfg()).clone();
    c.manual_rules = "blocked.example = tlsrec-tcp".into();
    sh.set_config(c);
    let mut app = open_flow(&sh, 443);
    run_app(&mut app, &client_hello("blocked.example"), 1)
        .await
        .unwrap();
    assert_eq!(dpi.split_hellos.load(SeqCst), 1);
    assert_eq!(sh.stats.snapshot().strategy_tlsrec_tcp, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn manual_direct_rule_overrides_learning_and_never_escalates() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let mut cfg = test_config();
    cfg.manual_rules = "blocked.example = direct\n".into();
    let sh = shared_with(cfg, conn, dummy_tls());
    let mut app = open_flow(&sh, 443);
    assert!(run_app(&mut app, &client_hello("blocked.example"), 1)
        .await
        .is_err());
    assert_eq!(dpi.blocked.load(SeqCst), 1);
    assert_eq!(dpi.split_hellos.load(SeqCst), 0);
    assert_eq!(
        state(&sh, "blocked.example"),
        State::Unknown,
        "manual flows never write learned state"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn manual_tlsrec_rule_applies_without_probing_direct() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let mut cfg = test_config();
    cfg.manual_rules = "blocked.example = tlsrec".into();
    let sh = shared_with(cfg, conn, dummy_tls());
    let mut app = open_flow(&sh, 443);
    run_app(&mut app, &client_hello("blocked.example"), 1)
        .await
        .unwrap();
    assert_eq!(dpi.blocked.load(SeqCst), 0, "no plain attempt was made");
    assert_eq!(dpi.split_hellos.load(SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn total_failure_sets_cooldown_and_fails_open_to_direct() {
    // Middlebox that kills *everything* for the host, even fragmented hellos (matches "ample").
    let dpi = dpi_server("ample", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let mut app = open_flow(&sh, 443);
    let r = run_app(&mut app, &client_hello("sample.example"), 1).await;
    // The split point lands mid-host ("sample.example" -> "sample." | "example"), so "ample" stays whole
    // in the first record and the middlebox still matches: every strategy fails.
    assert!(r.is_err());
    assert_eq!(state(&sh, "sample.example"), State::TlsRecBad);
    let d = sh
        .strategy
        .lock()
        .unwrap()
        .decide(&key_for(&sh, "sample.example"), None, sh.now());
    assert_eq!(
        d.ladder,
        vec![Strategy::Direct],
        "cooling down: fail open to plain direct"
    );
    // After the cooldown expires the host is probed from scratch again.
    sh.clock_offset.fetch_add(3600, SeqCst);
    assert_eq!(state(&sh, "sample.example"), State::Unknown);
}

#[tokio::test(flavor = "multi_thread")]
async fn clienthello_arriving_in_pieces_is_reassembled_before_deciding() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let mut app = open_flow(&sh, 443);
    run_app(&mut app, &client_hello("blocked.example"), 5)
        .await
        .unwrap();
    assert_eq!(state(&sh, "blocked.example"), State::TlsRecGood);
}

#[tokio::test(flavor = "multi_thread")]
async fn clienthello_spanning_multiple_records_is_handled() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let hs = client_hello_handshake(Some("blocked.example"), 700);
    let mut raw = Vec::new();
    for c in hs.chunks(300) {
        raw.extend_from_slice(&one_record(c));
    }
    let mut app = open_flow(&sh, 443);
    run_app(&mut app, &raw, 1).await.unwrap();
    assert_eq!(state(&sh, "blocked.example"), State::TlsRecGood);
    assert_eq!(dpi.valid_hellos.load(SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_without_sni_is_never_split_and_keyed_by_ip() {
    let dpi = dpi_server("never-matches", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let raw = one_record(&client_hello_handshake(None, 0));
    let mut app = open_flow(&sh, 443);
    run_app(&mut app, &raw, 1).await.unwrap();
    assert_eq!(dpi.split_hellos.load(SeqCst), 0);
    assert_eq!(state(&sh, "203.0.113.10"), State::DirectGood);
}

#[tokio::test(flavor = "multi_thread")]
async fn non_tls_on_tls_port_passes_through_untouched() {
    let dpi = dpi_server("blocked.example", Block::Reset).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let mut app = open_flow(&sh, 443);
    app.write_all(b"GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n")
        .await
        .unwrap();
    let mut got = [0u8; 9];
    app.read_exact(&mut got).await.unwrap();
    assert_eq!(got, SERVER_HELLO);
    assert_eq!(sh.stats.snapshot().connections_direct, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_traffic_never_panics_or_wedges() {
    let dpi = dpi_server("blocked.example", Block::None).await;
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let mut garbage: Vec<Vec<u8>> = vec![
        vec![0x16, 0x03, 0x01, 0xff, 0xff, 1, 2, 3], // absurd record length
        vec![0x16, 0x03, 0x01, 0x00, 0x00],          // zero-length record
        vec![0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff], // huge handshake
        vec![0x00; 64],
        vec![0xff; 5000],
    ];
    let mut truncated = client_hello("trunc.example");
    truncated.truncate(40);
    garbage.push(truncated);
    for g in garbage {
        let (mut app, engine_side) = tokio::io::duplex(64 * 1024);
        let h = tokio::spawn(handle_tcp(sh.clone(), engine_side, dst(443)));
        app.write_all(&g).await.unwrap();
        app.shutdown().await.unwrap();
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(12), app.read_to_end(&mut sink)).await;
        let _ = tokio::time::timeout(Duration::from_secs(12), h)
            .await
            .expect("flow task must finish");
    }
    assert_eq!(sh.stats.snapshot().flows_active, 0, "no leaked flows");
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_connect_failure_is_not_learned_as_dpi() {
    let conn = TestConnector::new();
    // Nothing listens here.
    let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    conn.set_default_tcp(dead);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let mut app = open_flow(&sh, 443);
    app.write_all(&client_hello("unreachable.example"))
        .await
        .unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), app.read_to_end(&mut sink)).await;
    assert_eq!(state(&sh, "unreachable.example"), State::Unknown);
    assert!(sh.stats.snapshot().connections_failed >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn non_tls_ports_connect_immediately_for_server_speaks_first_protocols() {
    // e.g. SMTP/FTP banners: the server talks first, so we must not wait for client bytes.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        s.write_all(b"220 hello\r\n").await.unwrap();
        let mut b = [0u8; 8];
        let _ = s.read(&mut b).await;
    });
    let conn = TestConnector::new();
    conn.set_default_tcp(addr);
    let sh = shared_with(test_config(), conn, dummy_tls());
    let mut app = open_flow(&sh, 25);
    let mut banner = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(3), app.read_exact(&mut banner))
        .await
        .expect("banner")
        .unwrap();
    assert_eq!(&banner, b"220 hello\r\n");
}
