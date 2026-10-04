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
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const FIRST_FLIGHT_WAIT: Duration = Duration::from_secs(10);

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
    let key = Key::new(&sh.salt(), cfg.network_id, Family::of(&dst.ip()), &host);
    let manual = sh.rules().lookup(&host);
    let decision = sh
        .strategy
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .decide(&key, manual, now);
    let learn = decision.source != Source::Manual;
    if cfg.verbose_hosts {
        log::debug!(
            "flow {host}: ladder {:?} source {:?}",
            decision.ladder,
            decision.source
        );
    }

    let mut pre = pre.ok();
    let mut last_err = io::Error::other("no strategy could be applied");
    let n = decision.ladder.len();
    for (i, strat) in decision.ladder.iter().copied().enumerate() {
        let last = i + 1 == n;
        let Some(chunks) = chunks_for(strat, &buf, &handshake, &info) else {
            // This strategy cannot be applied to this hello (e.g. no SNI): skip, don't learn.
            continue;
        };
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
        let outcome = attempt(&mut up, &chunks, wait).await;
        let report = |ok: bool| {
            if learn {
                sh.strategy
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .report(key, strat, ok, sh.now());
            }
        };
        match outcome {
            Attempt::Data(first_bytes) => {
                report(true);
                count_strategy(sh, strat);
                app.write_all(&first_bytes).await?;
                relay(sh, app, &mut up).await;
                return Ok(());
            }
            Attempt::Slow if last => {
                // Inconclusive and nothing left to try: keep this connection, learn nothing.
                count_strategy(sh, strat);
                relay(sh, app, &mut up).await;
                return Ok(());
            }
            Attempt::Slow => {
                report(false);
                inc(&sh.stats.escalations);
                last_err = io::Error::new(io::ErrorKind::TimedOut, "no server response");
            }
            Attempt::Failed(e) => {
                report(false);
                inc(&sh.stats.escalations);
                last_err = e;
            }
        }
    }
    Err(last_err)
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
    let mut b = vec![0u8; 16 * 1024];
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

async fn relay<A, B>(sh: &Shared, a: &mut A, b: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if let Ok((up, down)) = tokio::io::copy_bidirectional(a, b).await {
        add(&sh.stats.bytes_up, up);
        add(&sh.stats.bytes_down, down);
    }
}
