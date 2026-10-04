//! A stream adapter that rewrites the *first* write (a TLS ClientHello) according to a split mode.
//! Used by diagnostics so a real TLS handshake can be driven through the same bypass logic the
//! flow handler uses.

use nivyx_core::tls::{self, Parsed, SplitMode};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct SplitFirstWrite<S> {
    inner: S,
    mode: Option<SplitMode>,
    state: State,
}

enum State {
    Fresh,
    Sending {
        chunks: Vec<Vec<u8>>,
        idx: usize,
        off: usize,
        flushed: bool,
        orig_len: usize,
    },
    Done,
}

impl<S> SplitFirstWrite<S> {
    pub fn new(inner: S, mode: Option<SplitMode>) -> Self {
        SplitFirstWrite {
            inner,
            mode,
            state: if mode.is_some() {
                State::Fresh
            } else {
                State::Done
            },
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SplitFirstWrite<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SplitFirstWrite<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if matches!(this.state, State::Fresh) {
            let chunks = match (this.mode, tls::parse_client_hello(buf)) {
                (Some(mode), Parsed::Hello { info, handshake }) => {
                    tls::split_client_hello(&handshake, &info, mode)
                        .ok()
                        .map(|mut c| {
                            if buf.len() > info.consumed {
                                c.push(buf[info.consumed..].to_vec());
                            }
                            c
                        })
                }
                _ => None,
            };
            this.state = match chunks {
                Some(chunks) => State::Sending {
                    chunks,
                    idx: 0,
                    off: 0,
                    flushed: false,
                    orig_len: buf.len(),
                },
                None => State::Done,
            };
        }
        if let State::Sending {
            chunks,
            idx,
            off,
            flushed,
            orig_len,
        } = &mut this.state
        {
            while *idx < chunks.len() {
                while *off < chunks[*idx].len() {
                    let n =
                        ready!(Pin::new(&mut this.inner).poll_write(cx, &chunks[*idx][*off..]))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    *off += n;
                }
                if !*flushed {
                    ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                    *flushed = true;
                }
                *idx += 1;
                *off = 0;
                *flushed = false;
            }
            let n = *orig_len;
            this.state = State::Done;
            return Poll::Ready(Ok(n));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nivyx_core::tls::testutil::client_hello;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn through(mode: Option<SplitMode>, data: &[u8]) -> Vec<u8> {
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let mut w = SplitFirstWrite::new(a, mode);
        w.write_all(data).await.unwrap();
        w.write_all(b"second write untouched").await.unwrap();
        w.flush().await.unwrap();
        drop(w);
        let mut out = Vec::new();
        b.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn first_write_is_split_and_later_writes_pass_through() {
        let hello = client_hello("split.example.org");
        for mode in [SplitMode::Records, SplitMode::RecordsTcp] {
            let out = through(Some(mode), &hello).await;
            let tail = b"second write untouched";
            assert!(out.ends_with(tail));
            let wire = &out[..out.len() - tail.len()];
            match tls::parse_client_hello(wire) {
                Parsed::Hello { info, .. } => {
                    assert_eq!(info.record_count, 2);
                    assert_eq!(info.sni.as_deref(), Some("split.example.org"));
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn no_mode_or_non_tls_is_a_pure_passthrough() {
        let hello = client_hello("split.example.org");
        let out = through(None, &hello).await;
        assert_eq!(&out[..hello.len()], &hello[..]);
        let out = through(Some(SplitMode::Records), b"GET / HTTP/1.1\r\n\r\n").await;
        assert!(out.starts_with(b"GET / HTTP/1.1"));
    }
}
