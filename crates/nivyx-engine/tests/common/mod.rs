//! Local integration harness: fake DPI middlebox, fake DoH resolver, fake plain DNS, packet-level
//! "TUN" client, and a destination-remapping connector. No real network, no real censorship.
#![allow(dead_code)]

use nivyx_core::config::{Config, Resolver};
use nivyx_core::dns;
use nivyx_core::stats::Stats;
use nivyx_core::tls::{self, Parsed};
use nivyx_engine::connector::{BoxFut, Connector};
use nivyx_engine::Shared;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

pub const SERVER_HELLO: [u8; 9] = [0x16, 3, 3, 0, 4, 2, 0, 0, 0];

// ---------------------------------------------------------------- connector

#[derive(Default)]
pub struct TestConnector {
    tcp_map: Mutex<HashMap<SocketAddr, SocketAddr>>,
    udp_map: Mutex<HashMap<SocketAddr, SocketAddr>>,
    pub default_tcp: Mutex<Option<SocketAddr>>,
    pub tcp_connects: AtomicUsize,
}

impl TestConnector {
    pub fn new() -> Arc<TestConnector> {
        Arc::new(TestConnector::default())
    }
    pub fn map_tcp(&self, from: SocketAddr, to: SocketAddr) {
        self.tcp_map.lock().unwrap().insert(from, to);
    }
    pub fn map_udp(&self, from: SocketAddr, to: SocketAddr) {
        self.udp_map.lock().unwrap().insert(from, to);
    }
    pub fn set_default_tcp(&self, to: SocketAddr) {
        *self.default_tcp.lock().unwrap() = Some(to);
    }
}

impl Connector for TestConnector {
    fn tcp(&self, addr: SocketAddr, timeout: Duration) -> BoxFut<TcpStream> {
        self.tcp_connects.fetch_add(1, SeqCst);
        let target = self
            .tcp_map
            .lock()
            .unwrap()
            .get(&addr)
            .copied()
            .or(*self.default_tcp.lock().unwrap())
            .unwrap_or(addr);
        Box::pin(async move {
            let s = tokio::time::timeout(timeout, TcpStream::connect(target))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
            s.set_nodelay(true)?;
            Ok(s)
        })
    }

    fn udp(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let target = self
            .udp_map
            .lock()
            .unwrap()
            .get(&addr)
            .copied()
            .unwrap_or(addr);
        let s = std::net::UdpSocket::bind("127.0.0.1:0")?;
        s.connect(target)?;
        s.set_nonblocking(true)?;
        UdpSocket::from_std(s)
    }
}

// ---------------------------------------------------------------- TLS fixtures

pub struct Pki {
    pub server: Arc<rustls::ServerConfig>,
    pub client: Arc<rustls::ClientConfig>,
}

pub fn pki() -> Pki {
    let ck =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap();
    let der = ck.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key.into())
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Pki {
        server: Arc::new(server),
        client: Arc::new(client),
    }
}

// ---------------------------------------------------------------- fake DPI + server

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Block {
    None,
    /// Inject a TCP reset when the first segment contains the blocked host name in clear.
    Reset,
    /// Silently stop answering.
    Blackhole,
}

pub struct Dpi {
    pub addr: SocketAddr,
    pub connections: Arc<AtomicUsize>,
    pub blocked: Arc<AtomicUsize>,
    pub served: Arc<AtomicUsize>,
    /// Hellos that arrived intact and parseable, as a real server would see them.
    pub valid_hellos: Arc<AtomicUsize>,
    /// Hellos that arrived split over more than one TLS record.
    pub split_hellos: Arc<AtomicUsize>,
}

/// A naive DPI box in front of an echo "TLS" server: it pattern-matches `blocked_host` against the
/// raw bytes of the first read, like most real middleboxes that do not reassemble records.
pub async fn dpi_server(blocked_host: &'static str, mode: Block) -> Dpi {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let d = Dpi {
        addr,
        connections: Arc::new(AtomicUsize::new(0)),
        blocked: Arc::new(AtomicUsize::new(0)),
        served: Arc::new(AtomicUsize::new(0)),
        valid_hellos: Arc::new(AtomicUsize::new(0)),
        split_hellos: Arc::new(AtomicUsize::new(0)),
    };
    let (c, b, s, v, sp) = (
        d.connections.clone(),
        d.blocked.clone(),
        d.served.clone(),
        d.valid_hellos.clone(),
        d.split_hellos.clone(),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                return;
            };
            let (c, b, s, v, sp) = (c.clone(), b.clone(), s.clone(), v.clone(), sp.clone());
            tokio::spawn(async move {
                c.fetch_add(1, SeqCst);
                let mut first = vec![0u8; 16384];
                let Ok(n) = sock.read(&mut first).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                first.truncate(n);
                let host = blocked_host.as_bytes();
                if mode != Block::None && first.windows(host.len()).any(|w| w == host) {
                    b.fetch_add(1, SeqCst);
                    match mode {
                        Block::Reset => {
                            let std_sock = sock.into_std().unwrap();
                            let _ =
                                socket2::SockRef::from(&std_sock).set_linger(Some(Duration::ZERO));
                            drop(std_sock);
                        }
                        _ => {
                            let mut sink = [0u8; 64];
                            while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
                        }
                    }
                    return;
                }
                // Reassemble like a real TLS server would.
                let mut acc = first;
                loop {
                    match tls::parse_client_hello(&acc) {
                        Parsed::Hello { info, .. } => {
                            v.fetch_add(1, SeqCst);
                            if info.record_count > 1 {
                                sp.fetch_add(1, SeqCst);
                            }
                            break;
                        }
                        Parsed::NeedMore => {
                            let mut more = vec![0u8; 4096];
                            match sock.read(&mut more).await {
                                Ok(n) if n > 0 => acc.extend_from_slice(&more[..n]),
                                _ => return,
                            }
                        }
                        _ => break, // not TLS: still serve (acts as plain echo)
                    }
                }
                s.fetch_add(1, SeqCst);
                if sock.write_all(&SERVER_HELLO).await.is_err() {
                    return;
                }
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            });
        }
    });
    d
}

// ---------------------------------------------------------------- fake DoH

pub const DOH_HEALTHY: u8 = 0;
pub const DOH_HTTP_503: u8 = 1;
pub const DOH_HANG: u8 = 2;

pub struct FakeDoh {
    pub resolver: Resolver,
    pub mode: Arc<AtomicU8>,
    pub requests: Arc<AtomicUsize>,
    pub connections: Arc<AtomicUsize>,
}

/// TLS-terminating DoH endpoint (HTTP/1.1, keep-alive) answering A queries from `answers`.
pub async fn fake_doh(pki: &Pki, name: &str, answers: Vec<(&'static str, Vec<IpAddr>)>) -> FakeDoh {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(pki.server.clone());
    let mode = Arc::new(AtomicU8::new(DOH_HEALTHY));
    let requests = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let answers: Arc<HashMap<String, Vec<IpAddr>>> = Arc::new(
        answers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    );
    let (m, r, c) = (mode.clone(), requests.clone(), connections.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let (acceptor, m, r, c, answers) = (
                acceptor.clone(),
                m.clone(),
                r.clone(),
                c.clone(),
                answers.clone(),
            );
            tokio::spawn(async move {
                c.fetch_add(1, SeqCst);
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                loop {
                    let Some(body) = read_http_request(&mut tls).await else {
                        return;
                    };
                    r.fetch_add(1, SeqCst);
                    match m.load(SeqCst) {
                        DOH_HANG => {
                            tokio::time::sleep(Duration::from_secs(60)).await;
                            return;
                        }
                        DOH_HTTP_503 => {
                            let _ = tls.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
                            continue;
                        }
                        _ => {}
                    }
                    let q = dns::parse_question(&body);
                    let resp = match q {
                        Some(q) => {
                            let addrs = if q.qtype == dns::TYPE_A {
                                answers.get(&q.name).cloned().unwrap_or_default()
                            } else {
                                vec![]
                            };
                            if addrs.is_empty() && !answers.contains_key(&q.name) {
                                dns::build_empty_response(&body, 3).unwrap()
                            } else {
                                dns::build_response(&body, &addrs, 120)
                            }
                        }
                        None => dns::build_empty_response(&body, 1).unwrap_or_default(),
                    };
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", resp.len());
                    let mut out = head.into_bytes();
                    out.extend_from_slice(&resp);
                    if tls.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    FakeDoh {
        resolver: Resolver {
            name: name.into(),
            url: format!("https://127.0.0.1:{port}/dns-query"),
            bootstrap: vec![],
        },
        mode,
        requests,
        connections,
    }
}

async fn read_http_request<S: AsyncRead + Unpin>(s: &mut S) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())?;
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Some(body)
}

// ---------------------------------------------------------------- fake plain DNS (UDP)

/// A plain-DNS server returning the configured A records (e.g. bogus ones to simulate poisoning).
pub async fn fake_plain_dns(
    answers: Vec<(&'static str, Vec<IpAddr>)>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let answers: HashMap<String, Vec<IpAddr>> = answers
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            h.fetch_add(1, SeqCst);
            let Some(q) = dns::parse_question(&buf[..n]) else {
                continue;
            };
            let r = match answers.get(&q.name) {
                Some(a) if q.qtype == dns::TYPE_A => dns::build_response(&buf[..n], a, 60),
                _ => dns::build_empty_response(&buf[..n], 3).unwrap(),
            };
            let _ = sock.send_to(&r, peer).await;
        }
    });
    (addr, hits)
}

// ---------------------------------------------------------------- config / shared helpers

pub fn test_config() -> Config {
    Config {
        salt: "harness".into(),
        network_id: 1,
        first_byte_timeout_ms: 500,
        connect_timeout_ms: 2000,
        resolvers: vec![],
        ..Config::default()
    }
}

pub fn shared_with(
    cfg: Config,
    connector: Arc<TestConnector>,
    tls: Arc<rustls::ClientConfig>,
) -> Arc<Shared> {
    Shared::new(cfg, Arc::new(Stats::default()), connector, tls)
}

pub fn dummy_tls() -> Arc<rustls::ClientConfig> {
    nivyx_engine::doh::tls_config()
}

pub fn dst(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), port)
}

// ---------------------------------------------------------------- packet-level TUN peer

/// Packet-oriented in-memory TUN device (one packet per read/write, like a real TUN fd).
pub struct FakeTun {
    pub from_apps: mpsc::UnboundedReceiver<Vec<u8>>,
    pub to_apps: mpsc::UnboundedSender<Vec<u8>>,
}

pub struct TunPeer {
    pub send: mpsc::UnboundedSender<Vec<u8>>,
    pub recv: mpsc::UnboundedReceiver<Vec<u8>>,
}

pub fn fake_tun() -> (FakeTun, TunPeer) {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    (
        FakeTun {
            from_apps: a_rx,
            to_apps: b_tx,
        },
        TunPeer {
            send: a_tx,
            recv: b_rx,
        },
    )
}

impl AsyncRead for FakeTun {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.from_apps.poll_recv(cx) {
            Poll::Ready(Some(p)) => {
                let n = p.len().min(buf.remaining());
                buf.put_slice(&p[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for FakeTun {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _ = self.to_apps.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Drive one app-side TLS-ish exchange over `app`: send `hello` (in `chunks` pieces), expect the
/// fake ServerHello, then a ping/echo round trip.
pub async fn run_app<S: AsyncRead + AsyncWrite + Unpin>(
    app: &mut S,
    hello: &[u8],
    chunks: usize,
) -> io::Result<()> {
    let step = hello.len().div_ceil(chunks.max(1));
    for c in hello.chunks(step) {
        app.write_all(c).await?;
        app.flush().await?;
        if chunks > 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let mut got = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(8), app.read_exact(&mut got))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no server hello"))??;
    assert_eq!(got, SERVER_HELLO);
    app.write_all(b"ping").await?;
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut echo))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no echo"))??;
    assert_eq!(&echo, b"ping");
    Ok(())
}
