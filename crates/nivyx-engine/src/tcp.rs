//! TCP flow handling: terminate the app's connection locally, connect out through a protected
//! socket, and for TLS flows apply the strategy ladder to the ClientHello.
//!
//! Because the app-facing TCP session is terminated inside the userspace stack, the ClientHello
//! is fully buffered before anything leaves the device. A failed attempt can therefore be retried
//! with the next strategy on a fresh upstream connection without the app noticing.

use crate::{FlowGuard, Shared};
use nivyx_core::config::Config;
use nivyx_core::stats::{add, inc};
use nivyx_core::strategy::{Family, Key, Source, Strategy};
use nivyx_core::tls::{self, ClientHelloInfo, Parsed, SplitMode};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Notify;

const FIRST_FLIGHT_WAIT: Duration = Duration::from_secs(10);
/// Per-direction relay buffer. Idle flows pay for this twice, so it is kept small (measured in docs/performance.md).
const RELAY_BUF: usize = 4096;

pub async fn handle_tcp<S>(sh: Arc<Shared>, mut app: S, dst: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _g = FlowGuard::new(&sh.stats);
    inc(&sh.stats.connections_total);
    let cfg = sh.cfg();
    let result = if cfg.tls_ports.contains(&dst.port()) {
        tls_flow(&sh, &cfg, &mut app, dst).await
    } else {
        plain_flow(&sh, &cfg, &mut app, dst).await
    };
    if let Err(e) = result {
        inc(&sh.stats.connections_failed);
        log::debug!("tcp flow ended with error: {e}");
    }
    let _ = app.shutdown().await;
}

async fn plain_flow<S>(
    sh: &Arc<Shared>,
    cfg: &Config,
    app: &mut S,
    dst: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut up = sh
        .connector
        .tcp(dst, Duration::from_millis(cfg.connect_timeout_ms))
        .await?;
    inc(&sh.stats.connections_direct);
    relay(sh, app, &mut up).await;
    Ok(())
}

async fn tls_flow<S>(sh: &Arc<Shared>, cfg: &Config, app: &mut S, dst: SocketAddr) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms);
    // Connect while waiting for the client's first flight: saves a round trip.
    let (pre, first) = tokio::join!(
        sh.connector.tcp(dst, connect_timeout),
        read_first_flight(app)
    );
    let (buf, parsed) = first?;

    let (info, handshake) = match parsed {
        Parsed::Hello { info, handshake } => (info, handshake),
        _ => {
            // Not a (valid) ClientHello: plain passthrough.
            let mut up = pre?;
            if !buf.is_empty() {
                up.write_all(&buf).await?;
            }
            inc(&sh.stats.connections_direct);
            relay(sh, app, &mut up).await;
            return Ok(());
        }
    };

    let host = info.sni.clone().unwrap_or_else(|| dst.ip().to_string());
    let now = sh.now();
    if let Some(sni) = &info.sni {
        sh.names
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(dst.ip(), sni, 300, now);
    }
    let salt = sh.salt();
    let fam_v = Family::of(&dst.ip());
    let key = Key::new(&salt, cfg.network_id, fam_v, &host);
    let family = Key::family(&salt, cfg.network_id, fam_v, &host);
    let manual = sh.rules().lookup(&host);
    let decision = sh
        .strategy
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .decide_scoped(&key, family.as_ref(), manual, now);
    let learn = decision.source != Source::Manual;
    if cfg.verbose_hosts {
        log::debug!(
            "flow {host}: ladder {:?} source {:?}",
            decision.ladder,
            decision.source
        );
    }
    let report = |strat: Strategy, ok: bool| {
        if learn {
            sh.strategy
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .report_scoped(key, family, strat, ok, sh.now());
        }
    };

    // Only strategies that can actually be realised for this hello (e.g. splitting needs an SNI),
    // so "last attempt" below is accurate. Plain direct is always possible and is the fail-open.
    let mut plan: Vec<(Strategy, Vec<Vec<u8>>)> = decision
        .ladder
        .iter()
        .filter_map(|s| chunks_for(*s, &buf, &handshake, &info).map(|c| (*s, c)))
        .collect();
    if plan.is_empty() {
        plan.push((Strategy::Direct, vec![buf.clone()]));
    }

    let mut pre = pre.ok();
    let mut last_err = io::Error::other("no strategy could be applied");
    let n = plan.len();
    for (i, (strat, chunks)) in plan.into_iter().enumerate() {
        let last = i + 1 == n;
        let mut up = match pre.take() {
            Some(s) => s,
            None => match sh.connector.tcp(dst, connect_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    last_err = e;
                    break; // connect failures say nothing about DPI
                }
            },
        };
        let wait = Duration::from_millis(cfg.first_byte_timeout_ms);
        match attempt(&mut up, &chunks, wait).await {
            Attempt::Data(first_bytes) if is_tls_reply(&first_bytes) => {
                report(strat, true);
                count_strategy(sh, strat);
                app.write_all(&first_bytes).await?;
                if strat == Strategy::Direct && learn {
                    let stall = Duration::from_millis(cfg.stall_timeout_ms);
                    relay_watched(sh, app, &mut up, stall, || {
                        // The handshake got through but the transfer froze or was reset: classic
                        // DPI throttling. The app's retry (and the rest of the domain) will bypass.
                        inc(&sh.stats.direct_stalls);
                        report(Strategy::Direct, false);
                    })
                    .await;
                } else {
                    relay(sh, app, &mut up).await;
                }
                return Ok(());
            }
            Attempt::Data(first_bytes) => {
                // Not a TLS handshake record: a block page or alert injected by a middlebox, or a
                // genuine server alert. Try the next strategy; on the last one hand it to the app.
                inc(&sh.stats.bogus_replies);
                if last {
                    count_strategy(sh, strat);
                    app.write_all(&first_bytes).await?;
                    relay(sh, app, &mut up).await;
                    return Ok(());
                }
                report(strat, false);
                inc(&sh.stats.escalations);
                last_err = io::Error::other("non-TLS reply to ClientHello");
            }
            Attempt::Slow if last => {
                // Inconclusive and nothing left to try: keep this connection, learn nothing.
                count_strategy(sh, strat);
                relay(sh, app, &mut up).await;
                return Ok(());
            }
            Attempt::Slow => {
                report(strat, false);
                inc(&sh.stats.escalations);
                last_err = io::Error::new(io::ErrorKind::TimedOut, "no server response");
            }
            Attempt::Failed(e) => {
                report(strat, false);
                inc(&sh.stats.escalations);
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// A server's first bytes after a ClientHello are always a TLS handshake record
/// (ServerHello or HelloRetryRequest). Anything else did not come from a working TLS server.
pub fn is_tls_reply(b: &[u8]) -> bool {
    match b {
        [] => false,
        [t] => *t == 0x16,
        [t, v, ..] => *t == 0x16 && *v == 0x03,
    }
}

fn count_strategy(sh: &Shared, s: Strategy) {
    match s {
        Strategy::Direct => inc(&sh.stats.connections_direct),
        Strategy::TlsRec => {
            inc(&sh.stats.connections_bypassed);
            inc(&sh.stats.strategy_tlsrec);
        }
        Strategy::TlsRecTcp => {
            inc(&sh.stats.connections_bypassed);
            inc(&sh.stats.strategy_tlsrec_tcp);
        }
    }
}

/// The byte chunks (each written and flushed separately) that realise `strat`.
pub fn chunks_for(
    strat: Strategy,
    raw: &[u8],
    handshake: &[u8],
    info: &ClientHelloInfo,
) -> Option<Vec<Vec<u8>>> {
    let mode = match strat {
        Strategy::Direct => return Some(vec![raw.to_vec()]),
        Strategy::TlsRec => SplitMode::Records,
        Strategy::TlsRecTcp => SplitMode::RecordsTcp,
    };
    let mut chunks = tls::split_client_hello(handshake, info, mode).ok()?;
    if raw.len() > info.consumed {
        chunks.push(raw[info.consumed..].to_vec());
    }
    Some(chunks)
}

enum Attempt {
    /// First bytes the server sent: the strategy worked.
    Data(Vec<u8>),
    /// Nothing arrived in time and the connection is still open.
    Slow,
    /// Reset, EOF or write error before any server data.
    Failed(io::Error),
}

async fn attempt(up: &mut TcpStream, chunks: &[Vec<u8>], wait: Duration) -> Attempt {
    for c in chunks {
        if let Err(e) = up.write_all(c).await {
            return Attempt::Failed(e);
        }
        if let Err(e) = up.flush().await {
            return Attempt::Failed(e);
        }
    }
    let mut b = vec![0u8; RELAY_BUF];
    match tokio::time::timeout(wait, up.read(&mut b)).await {
        Ok(Ok(0)) => Attempt::Failed(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "closed before any response",
        )),
        Ok(Ok(n)) => {
            b.truncate(n);
            Attempt::Data(b)
        }
        Ok(Err(e)) => Attempt::Failed(e),
        Err(_) => Attempt::Slow,
    }
}

/// Read the client's first bytes until a ClientHello is complete (or clearly isn't one).
pub async fn read_first_flight<S: AsyncRead + Unpin>(app: &mut S) -> io::Result<(Vec<u8>, Parsed)> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + FIRST_FLIGHT_WAIT;
    loop {
        match tokio::time::timeout_at(deadline, app.read(&mut chunk)).await {
            Err(_) => return Ok((buf, Parsed::NotClientHello)), // client silent: treat as non-TLS, passthrough
            Ok(Err(e)) => return Err(e),
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed before sending",
                ))
            }
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
        match tls::parse_client_hello(&buf) {
            Parsed::NeedMore => continue,
            p => return Ok((buf, p)),
        }
    }
}

/// Server bytes after which a direct flow is considered past the point where DPI freezes it.
pub const STALL_WATCH_BYTES: u64 = 64 * 1024;

/// Upstream wrapper that records what the stall watcher needs. No timers of its own.
struct Metered<'a, S> {
    inner: &'a mut S,
    m: &'a Meter,
}

struct Meter {
    t0: tokio::time::Instant,
    down: AtomicU64,
    /// Milliseconds since `t0` of the app's latest write to the server.
    last_up_ms: AtomicU64,
    /// The app wrote and the server has not sent anything since.
    pending: AtomicBool,
    reset: AtomicBool,
    wrote: Notify,
}

impl Meter {
    fn ms(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }
}

fn is_reset(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.inner).poll_read(cx, buf);
        match &r {
            Poll::Ready(Ok(())) => {
                let n = (buf.filled().len() - before) as u64;
                if n > 0 {
                    self.m.down.fetch_add(n, Relaxed);
                    self.m.pending.store(false, Relaxed);
                }
            }
            Poll::Ready(Err(e)) if is_reset(e) => self.m.reset.store(true, Relaxed),
            _ => {}
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut *self.inner).poll_write(cx, buf);
        match &r {
            Poll::Ready(Ok(n)) if *n > 0 => {
                self.m.last_up_ms.store(self.m.ms(), Relaxed);
                self.m.pending.store(true, Relaxed);
                self.m.wrote.notify_one();
            }
            Poll::Ready(Err(e)) if is_reset(e) => self.m.reset.store(true, Relaxed),
            _ => {}
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// Relay a direct flow and call `early_failure` (at most once, as soon as it is known) if the flow
/// fails in a way that points at DPI: the server went silent for `stall` after the app wrote, or
/// the connection was reset, all before [`STALL_WATCH_BYTES`] arrived. Event-driven: the watcher
/// only wakes after app writes. The connection itself is left alone; only the learned decision
/// changes, so the app's retry takes the bypass path.
async fn relay_watched<A>(
    sh: &Shared,
    app: &mut A,
    up: &mut TcpStream,
    stall: Duration,
    early_failure: impl FnOnce(),
) where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let m = Meter {
        t0: tokio::time::Instant::now(),
        down: AtomicU64::new(0),
        last_up_ms: AtomicU64::new(0),
        pending: AtomicBool::new(false),
        reset: AtomicBool::new(false),
        wrote: Notify::new(),
    };
    let stall_ms = stall.as_millis() as u64;
    let watcher = async {
        loop {
            if m.down.load(Relaxed) >= STALL_WATCH_BYTES {
                return std::future::pending::<()>().await;
            }
            if m.pending.load(Relaxed) {
                let due = m.last_up_ms.load(Relaxed) + stall_ms;
                if m.ms() >= due {
                    return;
                }
                tokio::time::sleep_until(m.t0 + Duration::from_millis(due)).await;
            } else {
                m.wrote.notified().await;
            }
        }
    };
    let mut wrapped = Metered { inner: up, m: &m };
    let relay_fut = relay(sh, app, &mut wrapped);
    tokio::pin!(relay_fut);
    tokio::pin!(watcher);
    let stalled = tokio::select! {
        _ = &mut relay_fut => false,
        _ = &mut watcher => true,
    };
    if stalled {
        early_failure();
        // Keep relaying: the decision is what changes, not this connection.
        relay_fut.await;
    } else if m.reset.load(Relaxed) && m.down.load(Relaxed) < STALL_WATCH_BYTES {
        early_failure();
    }
}

async fn relay<A, B>(sh: &Shared, a: &mut A, b: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if let Ok((up, down)) =
        tokio::io::copy_bidirectional_with_sizes(a, b, RELAY_BUF, RELAY_BUF).await
    {
        add(&sh.stats.bytes_up, up);
        add(&sh.stats.bytes_down, down);
    }
}
