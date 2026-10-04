//! DNS interception: every DNS query that enters the TUN is answered here, over DoH by default.

use crate::{FlowGuard, Shared};
use nivyx_core::dns::{self, MAX_DNS_MESSAGE, TYPE_A, TYPE_AAAA};
use nivyx_core::quic::MAX_MAPPING_TTL;
use nivyx_core::stats::inc;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

const DOH_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(3500);
const SYSTEM_TIMEOUT: Duration = Duration::from_millis(3000);

/// Answer one wire-format DNS query. Always returns a response (SERVFAIL on total failure).
pub async fn resolve(sh: &Arc<Shared>, query: &[u8]) -> Option<Vec<u8>> {
    let q = dns::parse_question(query)?;
    inc(&sh.stats.dns_queries);
    let cfg = sh.cfg();
    let now = sh.now();

    // IPv6 is not being tunneled: tell apps there are no AAAA records so they stay on IPv4
    // (and therefore inside the TUN, where bypass applies) instead of leaking around it.
    if q.qtype == TYPE_AAAA && !sh.ipv6_active.load(Relaxed) && !dns::is_local_name(&q.name) {
        return dns::build_empty_response(query, 0);
    }

    if let Some(mut hit) = sh
        .dns_cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&q.name, q.qtype, now)
    {
        dns::set_id(&mut hit, q.id);
        inc(&sh.stats.dns_cache_hits);
        return Some(hit);
    }

    let local = dns::is_local_name(&q.name);
    let mut resp = None;
    if cfg.encrypted_dns && !local {
        resp = doh_failover(sh, &cfg.resolvers, query).await;
    }
    if resp.is_none() {
        // Local names, encrypted DNS disabled, or every DoH resolver failed: fail open to the
        // network's own resolver so a broken DoH path never means no DNS at all.
        resp = system_query(sh, &cfg.system_dns, query).await;
        if cfg.encrypted_dns && !local && resp.is_some() {
            log::debug!("DoH unavailable; answered via system resolver");
        }
    }
    let Some(mut resp) = resp else {
        inc(&sh.stats.dns_failures);
        return dns::build_empty_response(query, 2); // SERVFAIL
    };
    dns::set_id(&mut resp, q.id);
    if !local {
        sh.dns_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(&q.name, q.qtype, &resp, now);
        if matches!(q.qtype, TYPE_A | TYPE_AAAA) {
            if let Some(a) = dns::parse_answers(&resp) {
                let ttl = a.min_ttl.unwrap_or(60) as u64;
                let mut names = sh.names.lock().unwrap_or_else(|e| e.into_inner());
                for ip in a.addrs {
                    names.record(ip, &q.name, ttl.min(MAX_MAPPING_TTL), now);
                }
            }
        }
    }
    Some(resp)
}

async fn doh_failover(
    sh: &Arc<Shared>,
    resolvers: &[nivyx_core::config::Resolver],
    query: &[u8],
) -> Option<Vec<u8>> {
    if resolvers.is_empty() {
        return None;
    }
    let start = sh.dns_health.preferred.load(Relaxed) as usize % resolvers.len();
    for i in 0..resolvers.len() {
        let idx = (start + i) % resolvers.len();
        match sh
            .doh
            .query(&resolvers[idx], query, DOH_ATTEMPT_TIMEOUT)
            .await
        {
            Ok(r) if dns::is_response(&r) && dns::parse_answers(&r).is_some() => {
                sh.dns_health.preferred.store(idx as u32, Relaxed);
                sh.dns_health.consecutive_failures.store(0, Relaxed);
                sh.dns_health.last_ok.store(sh.now(), Relaxed);
                return Some(r);
            }
            Ok(_) => log::debug!("resolver {idx} returned an unparsable response"),
            Err(e) => log::debug!("resolver {idx} failed: {e}"),
        }
    }
    sh.dns_health.consecutive_failures.fetch_add(1, Relaxed);
    None
}

/// Plain DNS over a protected UDP socket to the network's own resolvers.
pub async fn system_query(sh: &Arc<Shared>, servers: &[IpAddr], query: &[u8]) -> Option<Vec<u8>> {
    for ip in servers.iter().take(3) {
        let addr = SocketAddr::new(*ip, 53);
        let Ok(sock) = sh.connector.udp(addr) else {
            continue;
        };
        if sock.send(query).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; MAX_DNS_MESSAGE];
        if let Ok(Ok(n)) = tokio::time::timeout(SYSTEM_TIMEOUT, sock.recv(&mut buf)).await {
            buf.truncate(n);
            if dns::is_response(&buf) {
                return Some(buf);
            }
        }
    }
    None
}

/// UDP DNS flow: each datagram is one query; answered concurrently so A and AAAA don't serialize.
pub async fn udp_dns<S>(sh: Arc<Shared>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _g = FlowGuard::new(&sh.stats);
    let (mut rd, wr) = tokio::io::split(stream);
    let wr = Arc::new(Mutex::new(wr));
    let mut buf = vec![0u8; MAX_DNS_MESSAGE];
    loop {
        let n = match tokio::time::timeout(crate::UDP_IDLE_TIMEOUT, rd.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        let q = buf[..n].to_vec();
        let (sh2, wr2) = (sh.clone(), wr.clone());
        tokio::spawn(async move {
            if let Some(r) = resolve(&sh2, &q).await {
                let _ = wr2.lock().await.write_all(&r).await;
            }
        });
    }
}

/// DNS over TCP (RFC 1035 §4.2.2): 2-byte length prefix, possibly several queries per connection.
pub async fn tcp_dns<S>(sh: Arc<Shared>, mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _g = FlowGuard::new(&sh.stats);
    loop {
        let mut len = [0u8; 2];
        let r = tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut len)).await;
        if !matches!(r, Ok(Ok(_))) {
            break;
        }
        let n = u16::from_be_bytes(len) as usize;
        if !(12..=MAX_DNS_MESSAGE).contains(&n) {
            break;
        }
        let mut q = vec![0u8; n];
        if stream.read_exact(&mut q).await.is_err() {
            break;
        }
        let Some(resp) = resolve(&sh, &q).await else {
            break;
        };
        let mut out = Vec::with_capacity(resp.len() + 2);
        out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
        out.extend_from_slice(&resp);
        if stream.write_all(&out).await.is_err() {
            break;
        }
    }
    let _ = io::Result::Ok(stream.shutdown().await);
}
