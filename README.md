# Nivyx Android

**System-wide local DPI bypass for Android. No remote VPN server.**

> **Status: v0.9.0-rc1 release candidate.** Built and tested on a Linux host. It has **not** been tested on a physical
> Android device or emulator yet, so it is not 1.0. See [docs/device-test-plan.md](docs/device-test-plan.md).

## What it is
Nivyx receives your phone's traffic locally and, when a site is blocked by deep-packet inspection, re-sends the TLS
ClientHello split into two TLS records so the blocker cannot read the host name. Everything else goes out unchanged.

* **Android shows a VPN key icon** because Nivyx uses `VpnService` for local traffic interception. **No remote VPN
  server is used.** Traffic is not tunneled anywhere; your **public IP does not change**.
* **HTTPS is not decrypted** and **no certificate is installed.**
* **No telemetry, analytics, crash reporting, ads, accounts or Nivyx servers.** Network requests: DNS-over-HTTPS to the
  resolver you choose, and a GitHub Releases check only when you tap *Check for updates*.

```
Apps → VpnService (local TUN) → Rust engine → protected direct sockets → Internet
                                 ├ DoH DNS   ├ per-host strategy (direct / tls-record-split)   └ QUIC fallback
```

## Features
Encrypted DNS with failover and fail-open to system DNS · automatic, explainable per-host/per-network strategy
learning with TTLs · manual rules (`example.com = direct|tlsrec|tlsrec-tcp`, `*.` wildcards) · QUIC fallback scoped to
affected hosts · network-change recovery · per-app exclusion · diagnostics (DNS poisoning check, HTTPS per strategy) ·
redacted support export · user-initiated, SHA-256-verified updates.

## Install
Download from [Releases](https://github.com/kadireren7/nivyx-android/releases). **An unsigned APK cannot be
installed**: sign it first ([docs/release.md](docs/release.md)). Allow "install unknown apps" for your browser/files app.
Supported: Android 5.0+ (minSdk 21), ABIs arm64-v8a, armeabi-v7a, x86_64. *Tested versions: none on a device yet.*

## Usage
Open Nivyx → **Start** → accept Android's VPN prompt. The home screen shows protection, network, DNS and counters.
*Diagnostics* checks one domain. *Settings* has resolver, IPv6, QUIC, per-app exclusions, battery guidance, manual rules.

## Limitations
ICMP/ping is not forwarded · after a client closes its side the connection closes both ways (no TCP half-close) ·
apps with their own DoH/strict Private DNS resolve outside Nivyx · IPv6 is tunneled only when the network has it ·
Always-on VPN with "block without VPN" overrides Nivyx's fail-open · real-network effectiveness depends on your ISP's
DPI and is unverified here.

## Performance
Idle 3.9 MB RSS, 3 threads, 0 CPU (host measurement). Details and caveats: [docs/performance.md](docs/performance.md).

## Development
```
cargo test --workspace                  # 100+ Rust tests incl. the local integration harness
./gradlew testDebugUnitTest lintDebug   # needs JDK 17, Android SDK 36, NDK 27.2, cargo-ndk, rustup android targets
./gradlew assembleRelease
```
Docs: [architecture](docs/architecture.md) · [performance](docs/performance.md) · [security](docs/security.md) ·
[third-party](docs/third-party.md) · [release](docs/release.md).

MIT © Kadir Eren Altintas
