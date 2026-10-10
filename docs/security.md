# Security review (self-audit, v1.0.0)

Not an independent audit. Findings and status:

| Area | Finding / measure |
|---|---|
| VPN socket loops | Every engine socket goes through `protect()` before connect; failures abort the connection and are counted. |
| Unsafe FFI | `nivyx-core` forbids unsafe. Unsafe exists only in `tun.rs` (read/write/fcntl/dup, each with SAFETY notes) and the logcat call. JNI uses registry ids (no raw pointers), `catch_unwind` on every entry, 256 KiB input caps. |
| Parser safety | ClientHello/DNS parsers are bounds-checked, size-capped (32 KiB hello, 16 records, 4 KiB DNS), proptest-fuzzed; DNS name compression loops are rejected. No `cargo-fuzz` target yet. |
| Integer overflow | Offsets use checked arithmetic or slice `get`; release profile keeps overflow behaviour defined by checked code paths. |
| Unbounded allocation | All tables/queues bounded (see `performance.md`); first-flight buffering capped. |
| Updater | GitHub-only HTTPS, host allowlist re-checked on every redirect, strict release JSON parsing, asset name must equal `nivyx-android-v<ver>.apk`, size caps, SHA-256 from `SHA256SUMS` required, file name derived from parsed version (no traversal), install needs user confirmation; Android enforces same-signature updates. |
| Config parsing | Size-capped JSON, clamped numbers, HTTPS-only resolver URLs. |
| Android components | Exported: launcher activity; `VpnService` (guarded by signature-level `BIND_VPN_SERVICE`); `BOOT_COMPLETED` receiver (protected broadcast). Provider and everything else not exported. PendingIntents immutable. No deep links. |
| Storage | `allowBackup=false`, backup/extraction rules exclude everything; learned cache holds salted host *hashes* only and is AES-GCM encrypted with an Android Keystore key (API 23+; nothing persisted below that). |
| Privacy | No telemetry/analytics/crash SaaS; logs bounded and redacted; hostnames in debug logs only if explicitly enabled. |
| Known gaps | No independent review; ipstack is a young third-party stack (patched copy vendored); `cargo-fuzz` not set up; `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` behaviour was seen working on one physical Android 16 tablet (rc1 build) and an API 34 emulator install; other Android versions are untested. |
