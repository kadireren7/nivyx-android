# Local patches to ipstack 1.0.1 (Apache-2.0)

Upstream: https://github.com/narrowlink/ipstack (see LICENSE in this directory).

`src/stream/tcp.rs`, three small changes, both marked `NIVYX PATCH`:

1. When the peer's FIN is processed, wake a parked `poll_read`.
2. `poll_read` returns EOF once the connection is in CloseWait/LastAck/TimeWait/Closed and the
   receive channel is drained.
3. When a RST arrives, wake parked readers *and writers* (a writer blocked on a full send window
   otherwise never learns the peer is gone).

Why: the stream keeps its own channel sender alive, so without the patch a reader never observes
a client close. Flows (and ~40 KB each) then stay allocated until the TCP idle timeout (45 min in
Nivyx). Found with the 1000-short-connection benchmark in `crates/nivyx-engine/examples/tunbench.rs`.
Examples and dev-dependencies were removed from the vendored copy.
