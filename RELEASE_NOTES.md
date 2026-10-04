Release candidate. **Not tested on a physical Android device or emulator.** Do not treat as 1.0.

* Local DPI bypass via TLS record splitting, DoH, learned per-host strategies, QUIC fallback.
* minSdk 21, arm64-v8a / armeabi-v7a / x86_64.
* The APK in this release is **unsigned** unless signing secrets were configured; sign it before installing (docs/release.md).
* Verify downloads with `SHA256SUMS`; SBOM attached.
