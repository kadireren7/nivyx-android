//! UDP flow relay with scoped QUIC rejection.

use crate::{FlowGuard, Shared};
use nivyx_core::quic;
use nivyx_core::stats::{add, inc};
use nivyx_core::strategy::{Family, Key};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, Instant};

const DGRAM_BUF: usize = 2048;

/// True when QUIC to `dst` must be rejected so the app falls back to TCP/TLS: only if a host
/// that *recently resolved to this exact address* is currently known to need bypass.
pub fn should_reject_quic(sh: &Shared, dst: &SocketAddr, first_datagram: &[u8]) -> bool {
    let cfg = sh.cfg();
    if !cfg.quic_fallback || dst.port() != 443 || !quic::is_quic_initial(first_datagram) {
        return false;
    }
    let now = sh.now();
    let hosts: Vec<String> = sh
        .names
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .hosts_for(&dst.ip(), now)
        .into_iter()
        .map(String::from)
        .collect();
    let salt = sh.salt();
    let rules = sh.rules();
    let eng = sh.strategy.lock().unwrap_or_else(|e| e.into_inner());
    hosts.iter().any(|h| {
        let key = Key::new(&salt, cfg.network_id, Family::of(&dst.ip()), h);
        eng.needs_bypass(&key, rules.lookup(h), now)
    })
}

pub async fn handle_udp<S>(sh: Arc<Shared>, app: S, dst: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _g = FlowGuard::new(&sh.stats);
    inc(&sh.stats.udp_flows);
    let (mut rd, mut wr) = tokio::io::split(app);
    let mut a = vec![0u8; DGRAM_BUF];
    let n = match rd.read(&mut a).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    if should_reject_quic(&sh, &dst, &a[..n]) {
        inc(&sh.stats.quic_rejected);
        return; // dropping the flow makes the app time out QUIC and retry over TCP
    }
    let Ok(sock) = sh.connector.udp(dst) else {
        return;
    };
    if sock.send(&a[..n]).await.is_err() {
        return;
    }
    add(&sh.stats.bytes_up, n as u64);
    let mut b = vec![0u8; DGRAM_BUF];
    let idle = sleep(crate::UDP_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            r = rd.read(&mut a) => match r {
                Ok(n) if n > 0 => {
                    if sock.send(&a[..n]).await.is_err() { break; }
                    add(&sh.stats.bytes_up, n as u64);
                    idle.as_mut().reset(Instant::now() + crate::UDP_IDLE_TIMEOUT);
                }
                _ => break,
            },
            r = sock.recv(&mut b) => match r {
                Ok(n) => {
                    if wr.write_all(&b[..n]).await.is_err() { break; }
                    add(&sh.stats.bytes_down, n as u64);
                    idle.as_mut().reset(Instant::now() + crate::UDP_IDLE_TIMEOUT);
                }
                Err(_) => break,
            },
            _ = &mut idle => break,
        }
    }
}
