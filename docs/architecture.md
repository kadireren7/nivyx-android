# Architecture

```
Android apps
   │  (all public-IP traffic; LAN, multicast, CGNAT ranges are NOT routed in)
Android VpnService ── obtains a local TUN fd only
   │
TUN fd ──► Rust engine (libnivyx_jni.so)
             ipstack (userspace TCP/IP, tokio) ──► per-flow tasks
             ├─ DNS  (UDP/TCP :53)  → DoH (rustls) → failover → system DNS fallback
             ├─ TCP :443            → buffer ClientHello → strategy ladder → protected socket
             └─ UDP                 → QUIC scoped reject, else protected UDP relay
   │
protected sockets (VpnService.protect) ──► direct internet egress
```

No remote server, no relay, no TLS interception, no certificates. Public IP is unchanged.

## Layers and ownership
| Layer | Language | Owns |
|---|---|---|
| `crates/nivyx-core` | Rust, `#![forbid(unsafe_code)]` | TLS ClientHello parser/splitter, strategy engine, DNS wire helpers + cache, QUIC name map, config, redaction, fingerprint |
| `crates/nivyx-engine` | Rust | TUN device, protected connector, DoH client, flow handlers, diagnostics |
| `crates/nivyx-jni` | Rust | Minimal JNI surface (registry ids, `catch_unwind`, bounded inputs) |
| `app/` | Kotlin/Compose | Lifecycle, consent, foreground service, notification, UI, settings, connectivity callbacks, updater |

Kotlin never touches a packet.

## Forwarding-layer choice
Chosen: **ipstack 1.0.1** (Apache-2.0), vendored in `third_party/ipstack` with a small documented patch
(`NIVYX-PATCHES.md`). Reasons: async userspace stack with IPv4+IPv6, TCP and UDP; each TCP flow is exposed as an
`AsyncRead/Write` stream whose destination is the original one — exactly what a transparent proxy needs — and
the app-side connection is terminated locally, so the ClientHello can be fully buffered and a failed attempt
retried on a fresh upstream socket without the app noticing. Writing our own TCP/IP stack was rejected.

Measured result (see `performance.md`): idle 3.9 MB RSS / 3 threads / 0 CPU; ~25 KB per open flow; >1.9 Gbit/s on a
host core. **Not measured:** alternative stacks (smoltcp, tun2proxy). The measurements of the chosen stack are far
inside the low-end-device budget, so no alternative was prototyped; this is a decision by sufficiency, not a
head-to-head comparison. Benchmarking bugs found in ipstack (flows never released after FIN/RST) were fixed in the
vendored copy rather than switching stacks.

Known ipstack limits: after the client's FIN, ipstack closes both directions (no half-close); ICMP is not forwarded.

## Strategy engine
Per `(network fingerprint, address family, salted host hash)` it keeps, per strategy (`direct`, `tlsrec`,
`tlsrec-tcp`), a good/bad slot with TTL. Ladder = strategies not in a bad cooldown, known-good first, canonical
order otherwise; if all are cooling down it fails open to `direct`. Manual rules always win; wildcard rules need an
explicit `*.`; nothing is inherited across sibling hosts. Defaults: direct-good 1 h, direct-bad 30 min,
tlsrec-good 6 h, tlsrec-bad 10 min. Bounded to 4096 scopes (configurable).

## TLS record split
The first client flight is parsed (partial segments, multi-record hellos, malformed input handled; 32 KiB cap).
`tlsrec` re-encodes the handshake as two records split in the middle of the SNI host name, written in one segment;
`tlsrec-tcp` additionally writes them as two flushed TCP writes. The handshake bytes are never altered.

## DNS
All port-53 traffic entering the TUN is answered locally: DoH (Cloudflare, Google, Quad9 interleaved by default,
custom URL supported), id zeroed on the wire, keep-alive pool, failover, 10–300 s bounded cache. Local names
(`.local`, `.lan`, single label, private reverse zones) go to the network's own resolver. If every DoH resolver
fails the system resolver answers (fail-open; also keeps captive portals working). AAAA is answered empty while
IPv6 is not tunneled so apps stay inside the tunnel.

## QUIC
UDP/443 QUIC Initial packets are rejected only when a hostname that resolved to that exact IP within the last
≤5 minutes currently needs bypass; apps then fall back to TCP/TLS. Everything else passes.

## Routing, loops, per-app exclusion
Routes = public IPv4 space minus RFC1918/CGNAT/link-local/loopback/multicast (51 CIDRs), plus `2000::/3` when IPv6
is tunneled. Every Nivyx-owned outbound socket is passed through `VpnService.protect()` before connecting, so no
route loop is possible. Per-app exclusion uses `addDisallowedApplication`.

## Fail-open
* Teardown always closes the TUN first, then stops the engine.
* A watchdog (10 s, no wakeups beyond that) checks the engine's `alive` flag; a dead packet loop closes the TUN and
  restarts (max 3 times / 2 min, then stops and reports).
* Process death closes the TUN in the kernel; `START_STICKY` resumes only if the user's last intent was "on".
* Limit: with Android "Always-on VPN + Block connections without VPN" enabled by the user, Android itself blocks
  traffic while Nivyx is down; Nivyx cannot override that.

## Network changes
`NetworkMonitor` tracks the *underlying* (non-VPN) network (the VPN itself is the default network while active),
ranks it like Android does, debounces 400 ms, hashes transport+gateway+subnet+DNS(+carrier MCC/MNC) with a
per-install salt, calls `networkChanged` (flushes DNS/name caches and pooled DoH connections; learned data stays
scoped by fingerprint) and `setUnderlyingNetworks`. IPv6 availability flips re-establish the interface.
