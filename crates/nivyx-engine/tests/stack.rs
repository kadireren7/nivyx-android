//! End-to-end through the real userspace TCP/IP stack: raw IPv4 packets in, raw packets out.

mod common;
use common::*;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use nivyx_core::dns::{self, TYPE_A};
use nivyx_core::stats::Stats;
use nivyx_core::tls::testutil::client_hello;
use nivyx_engine::Engine;
use std::net::IpAddr;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const APP: [u8; 4] = [198, 18, 0, 2];

struct Tcp {
    peer: TunPeer,
    dst: [u8; 4],
    dport: u16,
    sport: u16,
    seq: u32,
    ack: u32,
}

impl Tcp {
    fn pkt(&self, syn: bool, payload: &[u8]) -> Vec<u8> {
        let mut b =
            PacketBuilder::ipv4(APP, self.dst, 64).tcp(self.sport, self.dport, self.seq, 65535);
        if syn {
            b = b.syn();
        } else {
            b = b.ack(self.ack);
            if !payload.is_empty() {
                b = b.psh();
            }
        }
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    async fn recv_tcp(&mut self) -> Option<(bool, u32, Vec<u8>, bool)> {
        loop {
            let p = timeout(Duration::from_secs(5), self.peer.recv.recv())
                .await
                .ok()??;
            let s = SlicedPacket::from_ip(&p).ok()?;
            if let Some(TransportSlice::Tcp(t)) = s.transport {
                if t.destination_port() == self.sport {
                    return Some((
                        t.syn(),
                        t.sequence_number(),
                        t.payload().to_vec(),
                        t.rst() || t.fin(),
                    ));
                }
            }
        }
    }

    async fn connect(&mut self) {
        self.peer.send.send(self.pkt(true, &[])).unwrap();
        let (syn, server_seq, _, _) = self.recv_tcp().await.expect("SYN-ACK");
        assert!(syn);
        self.seq += 1;
        self.ack = server_seq.wrapping_add(1);
        self.peer.send.send(self.pkt(false, &[])).unwrap();
    }

    async fn send(&mut self, data: &[u8]) {
        self.peer.send.send(self.pkt(false, data)).unwrap();
        self.seq = self.seq.wrapping_add(data.len() as u32);
    }

    /// Read until `n` payload bytes arrived (acking as we go).
    async fn read_n(&mut self, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < n {
            let (_, seq, payload, closed) = self.recv_tcp().await.expect("data packet");
            if !payload.is_empty() && seq == self.ack {
                self.ack = self.ack.wrapping_add(payload.len() as u32);
                got.extend_from_slice(&payload);
                self.peer.send.send(self.pkt(false, &[])).unwrap();
            }
            if closed && got.len() < n {
                break;
            }
        }
        got
    }
}

fn engine_with(
    tun: FakeTun,
    cfg: nivyx_core::config::Config,
    conn: Arc<TestConnector>,
    tls: Arc<rustls::ClientConfig>,
) -> (Engine, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    let e = Engine::start_with(tun, cfg, stats.clone(), conn, tls).unwrap();
    (e, stats)
}

#[test]
fn blocked_tls_connection_is_bypassed_through_the_whole_stack() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (dpi, tun, peer) = rt.block_on(async {
        let dpi = dpi_server("blocked.example", Block::Reset).await;
        let (tun, peer) = fake_tun();
        (dpi, tun, peer)
    });
    let conn = TestConnector::new();
    conn.set_default_tcp(dpi.addr);
    let (mut engine, stats) = engine_with(tun, test_config(), conn, dummy_tls());

    rt.block_on(async {
        let mut c = Tcp {
            peer,
            dst: [203, 0, 113, 77],
            dport: 443,
            sport: 41000,
            seq: 1000,
            ack: 0,
        };
        c.connect().await;
        c.send(&client_hello("blocked.example")).await;
        let hello = c.read_n(SERVER_HELLO.len()).await;
        assert_eq!(hello, SERVER_HELLO);
        c.send(b"ping").await;
        assert_eq!(c.read_n(4).await, b"ping");
    });
    assert_eq!(dpi.blocked.load(SeqCst), 1);
    assert_eq!(dpi.split_hellos.load(SeqCst), 1);
    let s = stats.snapshot();
    assert_eq!(
        (s.connections_total, s.connections_bypassed, s.escalations),
        (1, 1, 1)
    );
    assert!(engine.stats_json().contains("\"connections_bypassed\":1"));
    engine.stop();
}

#[test]
fn dns_query_to_the_virtual_resolver_is_answered_over_doh_through_the_stack() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let pki = pki();
    let (doh, tun, mut peer) = rt.block_on(async {
        let doh = fake_doh(
            &pki,
            "p",
            vec![(
                "stack.example",
                vec!["192.0.2.55".parse::<IpAddr>().unwrap()],
            )],
        )
        .await;
        let (tun, peer) = fake_tun();
        (doh, tun, peer)
    });
    let mut cfg = test_config();
    cfg.resolvers = vec![doh.resolver.clone()];
    let (mut engine, _stats) = engine_with(tun, cfg, TestConnector::new(), pki.client.clone());

    rt.block_on(async {
        let q = dns::build_query(0xABCD, "stack.example", TYPE_A).unwrap();
        let mut out = Vec::new();
        PacketBuilder::ipv4(APP, [198, 18, 0, 1], 64)
            .udp(53533, 53)
            .write(&mut out, &q)
            .unwrap();
        peer.send.send(out).unwrap();
        let reply = loop {
            let p = timeout(Duration::from_secs(8), peer.recv.recv())
                .await
                .expect("dns reply")
                .unwrap();
            let s = SlicedPacket::from_ip(&p).unwrap();
            if let Some(TransportSlice::Udp(u)) = s.transport {
                if u.destination_port() == 53533 {
                    break u.payload().to_vec();
                }
            }
        };
        let a = dns::parse_answers(&reply).unwrap();
        assert_eq!(a.addrs, vec!["192.0.2.55".parse::<IpAddr>().unwrap()]);
        assert_eq!(&reply[..2], &[0xAB, 0xCD]);
    });
    assert_eq!(doh.requests.load(SeqCst), 1);
    engine.stop();
}

#[test]
fn engine_stops_promptly_and_is_idempotent() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (tun, _peer) = rt.block_on(async { fake_tun() });
    let (mut engine, _) = engine_with(tun, test_config(), TestConnector::new(), dummy_tls());
    let t = std::time::Instant::now();
    engine.stop();
    engine.stop();
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "stop took {:?}",
        t.elapsed()
    );
}
