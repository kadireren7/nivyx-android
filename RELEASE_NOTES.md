Nivyx Android 1.0.3, security update.

* Updated Rust dependencies for newly published advisories: rustls 0.23.46 (RUSTSEC-2026-0346/0347/0348/0349, used for encrypted DNS), rustls-webpki 0.103.17 (RUSTSEC-2026-0382), webpki-roots 1.0.12 (RUSTSEC-2026-0381), tokio 1.54.1 (RUSTSEC-2026-0386), rustix 1.1.6 (RUSTSEC-2026-0486). Update from 1.0.2 is recommended.
* No behaviour changes beyond 1.0.2, whose notes follow.

Nivyx Android 1.0.2, video and download reliability on filtered networks.

* A direct connection now counts as working only if the server answers with a real TLS handshake. Forged replies (block pages, injected alerts) move on to the TLS record split.
* Handshake works but the transfer freezes or is reset early (typical throttling of videos and large downloads): Nivyx now notices, marks direct as not working for that site, and the app's retry goes through the bypass.
* New CDN host names under a domain that already needed bypass (video servers often use a new name for every request) go straight to the bypass, and QUIC to them is rejected so apps fall back to TCP.
* New setting *Block all QUIC*, for networks that filter QUIC itself.
* If DoH is unreachable and the network's own DNS answers, that answer is no longer cached and expires within 10 s, so a censored answer cannot stick once DoH works again. Backup addresses added for the default DoH providers.
* Support bundle shows stalled direct flows, forged replies and plain-DNS fallbacks.
* Tested with the local fake-DPI harness and unit tests. This build has not yet been physically tested on a device or a real filtered network (see docs/device-test-plan.md).

* Verify downloads with `SHA256SUMS`; SBOM attached.
