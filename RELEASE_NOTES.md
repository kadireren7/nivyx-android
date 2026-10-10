Nivyx Android 1.0.0, first stable release.

* System-wide local DPI bypass: TLS record splitting, encrypted DNS (DoH), learned per-host strategies, QUIC fallback.
* Android 5.0+ (minSdk 21); arm64-v8a, armeabi-v7a, x86_64.
* Physically validated on one Android tablet against a real blocked network (Discord became reachable). Not every device, Android version, ABI or network has been tested.
* No telemetry, analytics, accounts or remote Nivyx backend. HTTPS is not decrypted and no certificate is installed.
* Android shows a VPN indicator because Nivyx uses `VpnService` to handle traffic locally. Nothing is tunneled to a remote server; your public IP is unchanged.
* Verify downloads with `SHA256SUMS`; SBOM attached.
