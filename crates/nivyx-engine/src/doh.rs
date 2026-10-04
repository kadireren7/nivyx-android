//! Minimal DNS-over-HTTPS (RFC 8484, HTTP/1.1 POST) client with failover and connection reuse.
//! All sockets come from the protected [`Connector`], so DoH never loops through the TUN.

use crate::connector::Connector;
use nivyx_core::config::{parse_doh_url, Resolver};
use rustls::pki_types::ServerName;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const IDLE_TTL: Duration = Duration::from_secs(45);
const MAX_IDLE_PER_RESOLVER: usize = 2;
const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;

pub fn tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider supports default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    Arc::new(cfg)
}

struct Idle {
    stream: TlsStream<TcpStream>,
    since: Instant,
}

pub struct Doh {
    tls: TlsConnector,
    connector: Arc<dyn Connector>,
    idle: Mutex<Vec<(String, Idle)>>,
}

impl Doh {
    pub fn new(connector: Arc<dyn Connector>, tls: Arc<rustls::ClientConfig>) -> Doh {
        Doh {
            tls: TlsConnector::from(tls),
            connector,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Drop pooled connections (e.g. after a network change).
    pub fn reset(&self) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn take_idle(&self, key: &str) -> Option<TlsStream<TcpStream>> {
        let mut g = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|(_, i)| i.since.elapsed() < IDLE_TTL);
        let pos = g.iter().position(|(k, _)| k == key)?;
        Some(g.remove(pos).1.stream)
    }

    fn put_idle(&self, key: &str, stream: TlsStream<TcpStream>) {
        let mut g = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if g.iter().filter(|(k, _)| k == key).count() < MAX_IDLE_PER_RESOLVER {
            g.push((
                key.to_string(),
                Idle {
                    stream,
                    since: Instant::now(),
                },
            ));
        }
    }

    async fn connect(&self, r: &Resolver, timeout: Duration) -> io::Result<TlsStream<TcpStream>> {
        let u = parse_doh_url(&r.url)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad DoH URL"))?;
        let (name, addrs): (ServerName<'static>, Vec<IpAddr>) = match u.host.parse::<IpAddr>() {
            Ok(ip) => (ServerName::IpAddress(ip.into()), vec![ip]),
            Err(_) => (
                ServerName::try_from(u.host.clone())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad host"))?,
                r.bootstrap.clone(),
            ),
        };
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address for resolver");
        for ip in addrs {
            let tcp = match self
                .connector
                .tcp(SocketAddr::new(ip, u.port), timeout)
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            match tokio::time::timeout(timeout, self.tls.connect(name.clone(), tcp)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = e,
                Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"),
            }
        }
        Err(last)
    }

    /// Resolve `query` (a wire-format DNS message) through resolver `r`.
    /// The query id is zeroed on the wire (RFC 8484 §4.1) and restored in the reply.
    pub async fn query(
        &self,
        r: &Resolver,
        query: &[u8],
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "short query"));
        }
        let mut wire = query.to_vec();
        wire[0] = 0;
        wire[1] = 0;
        let key = r.url.clone();
        // A pooled connection may have been closed by the server; retry once on a fresh one.
        if let Some(mut s) = self.take_idle(&key) {
            if let Ok(Ok((body, reusable))) =
                tokio::time::timeout(timeout, exchange(&mut s, r, &wire)).await
            {
                if reusable {
                    self.put_idle(&key, s);
                }
                return Ok(restore_id(body, query));
            }
        }
        let mut s = self.connect(r, timeout).await?;
        let (body, reusable) = tokio::time::timeout(timeout, exchange(&mut s, r, &wire))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoH request timed out"))??;
        if reusable {
            self.put_idle(&key, s);
        }
        Ok(restore_id(body, query))
    }
}

fn restore_id(mut body: Vec<u8>, query: &[u8]) -> Vec<u8> {
    if body.len() >= 2 {
        body[0] = query[0];
        body[1] = query[1];
    }
    body
}

async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    s: &mut S,
    r: &Resolver,
    wire: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    let u = parse_doh_url(&r.url)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad DoH URL"))?;
    let host_hdr = if u.port == 443 {
        if u.host.contains(':') {
            format!("[{}]", u.host)
        } else {
            u.host.clone()
        }
    } else if u.host.contains(':') {
        format!("[{}]:{}", u.host, u.port)
    } else {
        format!("{}:{}", u.host, u.port)
    };
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        u.path,
        host_hdr,
        wire.len()
    );
    let mut out = req.into_bytes();
    out.extend_from_slice(wire);
    s.write_all(&out).await?;
    s.flush().await?;
    read_response(s).await
}

/// Parse an HTTP/1.1 response. Returns `(body, connection_reusable)`.
pub(crate) async fn read_response<S: AsyncReadExt + Unpin>(
    s: &mut S,
) -> io::Result<(Vec<u8>, bool)> {
    let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    let head_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEADER {
            return Err(bad("header too large"));
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "closed before response",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| bad("non-utf8 header"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| bad("empty response"))?;
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or("");
    let status: u16 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| bad("bad status line"))?;
    if status != 200 {
        return Err(io::Error::other(format!("DoH HTTP status {status}")));
    }
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut close = version != "HTTP/1.1";
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
        match k.as_str() {
            "content-length" => {
                content_length = Some(v.parse().map_err(|_| bad("bad content-length"))?)
            }
            "transfer-encoding" if v.contains("chunked") => chunked = true,
            "connection" if v.contains("close") => close = true,
            _ => {}
        }
    }
    let mut rest = buf[head_end + 4..].to_vec();
    let body = if chunked {
        read_chunked(s, &mut rest).await?
    } else if let Some(len) = content_length {
        if len > MAX_BODY {
            return Err(bad("body too large"));
        }
        while rest.len() < len {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short body"));
            }
            rest.extend_from_slice(&tmp[..n]);
        }
        rest.truncate(len);
        rest
    } else {
        return Err(bad("response without length"));
    };
    Ok((body, !close))
}

async fn read_chunked<S: AsyncReadExt + Unpin>(
    s: &mut S,
    pending: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
    let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
    let mut body = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let line_end = loop {
            if let Some(p) = find(pending, b"\r\n") {
                break p;
            }
            if pending.len() > 64 {
                return Err(bad("bad chunk header"));
            }
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            pending.extend_from_slice(&tmp[..n]);
        };
        let size_str =
            std::str::from_utf8(&pending[..line_end]).map_err(|_| bad("bad chunk size"))?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad("bad chunk size"))?;
        pending.drain(..line_end + 2);
        if size == 0 {
            return Ok(body);
        }
        if body.len() + size > MAX_BODY {
            return Err(bad("body too large"));
        }
        while pending.len() < size + 2 {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            pending.extend_from_slice(&tmp[..n]);
        }
        body.extend_from_slice(&pending[..size]);
        pending.drain(..size + 2);
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(raw: &[u8]) -> io::Result<(Vec<u8>, bool)> {
        let mut c = std::io::Cursor::new(raw.to_vec());
        read_response(&mut c).await
    }

    #[tokio::test]
    async fn content_length_response() {
        let (b, reuse) = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: application/dns-message\r\n\r\nabc").await.unwrap();
        assert_eq!(b, b"abc");
        assert!(reuse);
    }

    #[tokio::test]
    async fn chunked_response_and_close() {
        let (b, reuse) = parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").await.unwrap();
        assert_eq!(b, b"abcde");
        assert!(!reuse);
    }

    #[tokio::test]
    async fn rejects_non_200_oversize_and_garbage() {
        assert!(parse(b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n")
            .await
            .is_err());
        assert!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n")
                .await
                .is_err()
        );
        assert!(parse(b"garbage").await.is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
            .await
            .is_err());
        assert!(
            parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
                .await
                .is_err()
        );
    }
}
