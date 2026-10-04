# Third-party components

Nivyx is MIT. Runtime dependencies (permissive licenses only; no GPL/AGPL):

**Native (Rust)** — see `Cargo.lock` / SBOM for exact versions: tokio (MIT), ipstack (Apache-2.0, vendored and
patched in `third_party/ipstack`), etherparse (MIT/Apache-2.0, via ipstack), rustls + tokio-rustls (Apache-2.0/MIT/ISC),
ring (ISC-style/OpenSSL-derived, see ring's LICENSE), webpki-roots (CDLA-Permissive-2.0, Mozilla CA data), socket2,
libc, log, serde, serde_json, sha2, jni (MIT/Apache-2.0).

**Android** — Kotlin stdlib/coroutines, AndroidX (core, lifecycle, activity, datastore, splashscreen) and Jetpack
Compose: Apache-2.0.

Run `scripts/make-sbom.py` for the machine-readable list.
