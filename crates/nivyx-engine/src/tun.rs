//! Async wrapper around the TUN file descriptor handed over by `VpnService`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    /// Shared with [`TunReleaser`]; cleared (under the lock) before the descriptor is closed.
    live: Arc<Mutex<Option<RawFd>>>,
}

/// Releases the TUN from outside the packet loop.
///
/// Dropping the engine runtime does not reliably drop the device (a stack task can be parked inside a
/// blocking drop while the runtime shuts down), and a TUN kept open with nothing forwarding is a black hole.
/// `release` therefore atomically points the descriptor at `/dev/null`, which drops our reference to the TUN
/// regardless of what any task is doing. Closing the descriptor number later is then harmless.
#[derive(Clone)]
pub struct TunReleaser(Arc<Mutex<Option<RawFd>>>);

impl TunReleaser {
    pub fn release(&self) {
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(fd) = *guard else { return };
        // SAFETY: the lock is held, and `TunDevice::drop` clears `live` before the descriptor is closed, so `fd`
        // still refers to our own duplicate. `null` is closed again after `dup2` copied it over `fd`.
        unsafe {
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if null >= 0 {
                if libc::dup2(null, fd) >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
                libc::close(null);
            }
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        *self.live.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn sys_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is a valid open descriptor for the duration of the call and `buf` is a valid writable slice.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn sys_write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `fd` is a valid open descriptor for the duration of the call and `buf` is a valid readable slice.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

impl TunDevice {
    pub fn releaser(&self) -> TunReleaser {
        TunReleaser(self.live.clone())
    }

    /// Duplicate `fd` (the caller keeps ownership of the original), make the copy non-blocking
    /// and take ownership of the copy.
    pub fn from_dup(fd: RawFd) -> io::Result<TunDevice> {
        // SAFETY: plain fcntl on an integer descriptor; the result is checked.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `dup` is a fresh, valid descriptor that nothing else owns.
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        set_nonblocking(owned.as_raw_fd())?;
        let live = Arc::new(Mutex::new(Some(owned.as_raw_fd())));
        Ok(TunDevice {
            fd: AsyncFd::new(owned)?,
            live,
        })
    }
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl calls on a valid descriptor; results are checked.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(g) => g?,
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| sys_read(inner.as_raw_fd(), unfilled)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.fd.poll_write_ready(cx) {
                Poll::Ready(g) => g?,
                Poll::Pending => return Poll::Pending,
            };
            match guard.try_io(|inner| sys_write(inner.as_raw_fd(), buf)) {
                Ok(r) => return Poll::Ready(r),
                Err(_would_block) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_byte(fd: RawFd) -> isize {
        // SAFETY: valid fd and a 1-byte stack buffer.
        unsafe { libc::write(fd, [0u8].as_ptr().cast(), 1) }
    }

    /// The pipe's read end stands in for the TUN: it only goes away when every reference to it is gone.
    #[tokio::test]
    async fn release_drops_the_tun_even_while_the_device_is_alive() {
        // SAFETY: plain libc calls on descriptors created here.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);

        let dev = TunDevice::from_dup(r).unwrap();
        unsafe { libc::close(r) }; // like the Kotlin side closing its copy first
        assert_eq!(write_byte(w), 1, "reader (our duplicate) is still open");

        dev.releaser().release();
        assert_eq!(
            write_byte(w),
            -1,
            "reader must be gone after release, device still alive"
        );

        dev.releaser().release(); // idempotent
        drop(dev); // closing the descriptor number afterwards is harmless
        unsafe { libc::close(w) };
    }

    #[tokio::test]
    async fn release_after_drop_never_touches_a_reused_descriptor() {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let dev = TunDevice::from_dup(fds[0]).unwrap();
        let releaser = dev.releaser();
        drop(dev);
        // Reuse whatever number the device had, then release: must be a no-op.
        let reused = unsafe { libc::dup(fds[1]) };
        releaser.release();
        assert_eq!(
            write_byte(reused),
            1,
            "unrelated descriptor must stay intact"
        );
        unsafe {
            libc::close(reused);
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
