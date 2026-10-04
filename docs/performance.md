# Performance

Low-end and old phones are a first-class target ("enabled all day without the user noticing").

## Method
`crates/nivyx-engine/examples/tunbench.rs`: the real engine on a **real Linux TUN device** inside an unprivileged
user+net namespace, driven by **real kernel TCP clients** (separate processes for server and load generator so the
engine process's own RSS/threads/CPU are measured via `/proc`). Release build, x86_64 Linux host, glibc malloc.
Reproduce: `cargo build --release -p nivyx-engine --example tunbench --features nivyx-core/testutil && unshare -rn target/release/examples/tunbench`.

**These are host numbers, not phone numbers.** No physical Android device or emulator was used (see "Not measured").

## Results (engine process only)
| Metric | Result |
|---|---|
| Idle, 10 s | RSS 3.9 MB, 3 threads, 0.00 s CPU |
| Threads under load | 5 (2 runtime workers + main + ≤2 blocking) |
| 64 B ping-pong RTT | 42–44 µs via engine vs 14–15 µs direct loopback (+~29 µs) |
| Download throughput, 1 flow | 1.97–2.07 Gbit/s at 132–158 % of one host core |
| Download throughput, 4 flows | 2.40–2.52 Gbit/s at 174–177 % |
| 10 000 short TLS connections, 50 parallel | 10 000 ok / 0 failed, ~9.4 k conn/s, p50 3.3 ms, p99 6.5 ms, 2.0 s total CPU (~200 µs/conn) |
| Flows after the burst | 0 (all released immediately) |
| Per open idle flow | ~25 KB (1000 flows: +24 MB RSS) |
| Release `libnivyx_jni.so` | 1.5 MB armv7, 2.4 MB arm64, 2.7 MB x86_64; whole 3-ABI release APK 8.0 MB |

Default `max_flows` is 1024 (≈25 MB worst case); configurable 16–8192.

## Bugs found by measuring (all fixed)
1. `TunDevice` registered with Tokio before a runtime existed → would have panicked on a real device.
2. ipstack never delivered EOF/RST to a parked relay task → every client-closed flow (~40 KB) lived until the
   45-minute idle timeout. Fixed in the vendored copy (`third_party/ipstack/NIVYX-PATCHES.md`).
   Before: 1000 closed flows still active, RSS 46 MB, p99 14 ms. After: 0 active, RSS 8 MB, p99 2 ms.

## Design measures for low-end devices
* Native hot path; Kotlin/Compose never sees packets. Event-driven I/O (epoll), no polling loops.
* 2 worker threads; 4 KiB relay buffers; bounded flows, DNS cache (≤4096), name map (4096), strategy table (4096),
  log ring (400 lines), DoH idle pool (2/resolver, 45 s).
* No periodic work except a 10 s watchdog (in-process timer, does not hold a wakelock) and a 10 min cache save.
* UI polls stats (2 s) only while visible (`WhileSubscribed` + lifecycle-aware collection).
* Release: LTO, `opt-level=s`, symbols stripped, R8 + resource shrinking. Packet copies: TUN→stack (1),
  stack→relay buffer (1), buffer→upstream socket (1); no Kotlin copies.
* Glibc does not return freed memory to the OS, so RSS stays high after a burst (not a leak: flow/cache counters
  return to zero). Android's allocator behaves differently; unmeasured.

## Leak / long-run tests (`crates/nivyx-engine/tests/longrun.rs`, in CI)
10 000 unique-host TLS flows with RSS-growth bound between 2 k and 10 k flows and zero residual flows; 3 000-query
DNS burst with bounded cache and connection reuse; 2 000 Wi-Fi/mobile/hotspot transitions with bounded tables;
60 engine start/stop cycles with no thread or RSS growth.

## 30-minute idle test
Real-time run (1800 s, release build, engine on an in-memory TUN, host also busy with builds):
RSS 4.57 → 2.68 MB (did not grow), threads 16 → 16 (the figure includes the test harness's own runtimes),
CPU 0.55 s over 30 min (≈0.03 % of one core), 979 voluntary context switches ≈ 0.54 wakeups/s for the whole process.
The wakeup source was not isolated; it is low but not zero. Reproduce:
`NIVYX_IDLE_SECS=1800 cargo test --release -p nivyx-engine --test longrun -- --ignored idle --nocapture`.
(The first run's assertion of ≤2 CPU ticks was too strict and failed at 55 ticks; the bound is now <0.1 % of a core.)

## Not measured (do on a device — see `device-test-plan.md`)
Real Android RSS/CPU/battery, armv7 runtime behaviour, wakeups on a phone, Android 5–7 behaviour, throughput over
real Wi-Fi/LTE, minSdk 21 devices. Alternative forwarding stacks were not benchmarked head-to-head.
