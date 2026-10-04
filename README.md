<p align="center">
  <img src="assets/logo-android.svg" alt="Nivyx Android" height="64">
</p>

<h3 align="center">Your phone. Your IP. No middleman. Just unblocked.</h3>

<p align="center">
  System-wide local DPI bypass for Android. <b>No remote VPN server.</b><br>
  Part of the <a href="https://github.com/kadireren7/nivyx">Nivyx</a> family.
</p>

<p align="center">
  <a href="https://github.com/kadireren7/nivyx-android/releases"><img alt="release" src="https://img.shields.io/github/v/release/kadireren7/nivyx-android?include_prereleases&color=10b981"></a>
  <img alt="license" src="https://img.shields.io/badge/license-MIT-0d9488">
  <img alt="min sdk" src="https://img.shields.io/badge/Android-5.0%2B-6ee7b7">
</p>

---

> **Honest status — v0.9.0-rc1.** Built and tested on Linux. **Not yet run on a physical phone**, so it is not 1.0.
> The real-device checklist is in [docs/device-test-plan.md](docs/device-test-plan.md).

## What it does

Censors read the host name in the first packet of an HTTPS connection. Nivyx quietly splits that packet so they can't.
Everything else is left alone.

```
App ─► local TUN ─► Nivyx engine (Rust) ─► your own connection ─► Internet
                      ├─ encrypted DNS (DoH)
                      ├─ per-host strategy: direct, or TLS record split
                      └─ QUIC fallback for hosts that need it
```

## The deal

| | |
|---|---|
| **Remote VPN server** | None. Traffic never leaves through us. |
| **Your public IP** | Unchanged. |
| **HTTPS** | Never decrypted. No certificate installed. |
| **Telemetry, analytics, ads, accounts** | None. Not one byte. |
| **If Nivyx breaks** | Fails open. The VPN interface closes first, your internet comes back. |
| **That VPN key icon** | Android shows it because Nivyx uses `VpnService` to catch traffic *locally*. That's all. |

## Why it's light

Built for old and low-end phones, not just flagships.

* Packet path is native Rust. Kotlin never touches a packet.
* Event-driven, no polling. Measured idle: **3.9 MB RAM, 3 threads, ~0 CPU** (host numbers, see [performance](docs/performance.md)).
* Every cache and queue is bounded; 10,000 connections leave nothing behind.
* Whole APK is about **8 MB** with three ABIs.

## Install

Grab the APK from [Releases](https://github.com/kadireren7/nivyx-android/releases). Release candidates ship **unsigned**:
sign it first ([docs/release.md](docs/release.md)), then allow "install unknown apps". Android 5.0+ · arm64-v8a · armeabi-v7a · x86_64.

## Use it

Open Nivyx → **Start** → accept Android's VPN prompt. Done.
*Diagnostics* tells you exactly what's going on with any domain. *Settings* has resolver, IPv6, QUIC, per-app
exclusions and manual rules (`example.com = tlsrec`).

## Limits, stated plainly

* No ping (ICMP isn't forwarded).
* Apps with their own DoH or strict Private DNS resolve outside Nivyx.
* Android's *Always-on VPN + block without VPN* overrides fail-open.
* Whether it beats **your** ISP's DPI is unproven until it runs on a real network.

## Build

```
cargo test --workspace                 # 100+ Rust tests incl. a local fake-DPI harness
./gradlew testDebugUnitTest lintDebug  # JDK 17, Android SDK 36, NDK 27.2, cargo-ndk
./gradlew assembleRelease
```

[architecture](docs/architecture.md) · [performance](docs/performance.md) · [security](docs/security.md) · [third-party](docs/third-party.md) · [release](docs/release.md)

<p align="center"><sub>MIT © Kadir Eren Altintas</sub></p>
