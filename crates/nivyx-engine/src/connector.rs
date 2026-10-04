//! Creation of outbound sockets. Every socket Nivyx owns is passed through
//! `VpnService.protect()` *before* it connects, so it can never be routed back into the TUN.

use nivyx_core::stats::Stats;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub type BoxFut<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// Platform hook that excludes a socket from the VPN (`VpnService.protect(fd)`).
pub trait Protector: Send + Sync + 'static {
    fn protect(&self, fd: i32) -> bool;
}

/// Outbound socket factory. Replaceable so the test harness can redirect destinations.
pub trait Connector: Send + Sync + 'static {
    fn tcp(&self, addr: SocketAddr, timeout: Duration) -> BoxFut<TcpStream>;
    /// A UDP socket already connected to `addr`.
    fn udp(&self, addr: SocketAddr) -> io::Result<UdpSocket>;
}

pub struct ProtectedConnector {
    protector: Arc<dyn Protector>,
    stats: Arc<Stats>,
}

impl ProtectedConnector {
    pub fn new(protector: Arc<dyn Protector>, stats: Arc<Stats>) -> Self {
        ProtectedConnector { protector, stats }
    }

    fn protect(&self, fd: i32) -> io::Result<()> {
        if self.protector.protect(fd) {
            Ok(())
        } else {
            self.stats.protect_failures.fetch_add(1, Relaxed);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService.protect failed",
            ))
        }
    }
}

impl Connector for ProtectedConnector {
    fn tcp(&self, addr: SocketAddr, timeout: Duration) -> BoxFut<TcpStream> {
        let sock = (|| {
            let s = if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }?;
            self.protect(s.as_raw_fd())?;
            s.set_nodelay(true)?;
            Ok::<_, io::Error>(s)
        })();
        Box::pin(async move {
            let sock = sock?;
            match tokio::time::timeout(timeout, sock.connect(addr)).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
            }
        })
    }

    fn udp(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .expect("literal");
        let std_sock = std::net::UdpSocket::bind(bind)?;
        self.protect(std_sock.as_raw_fd())?;
        std_sock.connect(addr)?;
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock)
    }
}
