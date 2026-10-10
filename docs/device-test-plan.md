# Physical device test plan

Boxes are checked only for what a person actually did on a real device. Everything else is **untested**.
Record device, Android version, ABI, carrier/ISP and result for each line.

**Physical validation performed (v0.9.0-rc1 signed build, one Android 16 tablet, one network where Discord was blocked, Oct 2026):**
installed the signed APK, launched it, completed the Android VPN consent flow, started the Nivyx service, ordinary
internet stayed usable, and Discord became reachable while Nivyx was active. The tablet's ABI, the exact network/ISP
and mobile-data behaviour were not recorded. The v1.0.1 signed release APK was validated separately (see the v1.0.1 entries below).

- [x] Clean install of the signed APK, one Android 16 tablet (rc1 build). Not yet: (also on an Android 5–7 and a 2 GB RAM device if available)
- [x] Start → Android VPN consent dialog → service starts (rc1, tablet). Notification and key icon were not separately recorded
- [x] Discord became reachable on a network where it was blocked (rc1, tablet). App vs. web not separately recorded
- [x] v1.0.1 (signed release APK, one Android tablet and one Android phone): app installs and launches; the Android VPN permission/service path works
- [x] v1.0.1 (tablet and phone): repeated rapid Start/Stop no longer leaves the device without internet
- [x] v1.0.1 (tablet and phone): normal Start works; normal Stop restores direct internet
- [x] v1.0.1 (tablet and phone): Discord is reachable while Nivyx is active on a network where it was blocked

Device models, Android versions, ABIs and network/ISP for the v1.0.1 runs were not recorded here. Results apply to those
devices and that network only.
- [ ] A site known to be blocked on your network opens; Diagnostics shows `direct` failing and `tlsrec` working
- [ ] Ordinary HTTPS sites work and are *not* fragmented (Diagnostics: direct OK)
- [ ] Wi-Fi; mobile data
- [ ] Switch Wi-Fi → mobile, mobile → Wi-Fi without toggling Nivyx
- [ ] Hotspot on/off
- [ ] Screen off 10 minutes, then browse
- [ ] Doze (leave idle overnight), then browse
- [ ] Reboot with "Start after reboot" on
- [ ] Force-stop the app: internet keeps working (fail-open) and Nivyx can be started again
- [ ] Airplane mode on/off; network loss and regain
- [ ] Block DoH (e.g. different network): DNS falls back and browsing still works
- [ ] YouTube/Chrome with QUIC on a network that blocks QUIC
- [ ] Excluded app (banking) works while excluded
- [ ] Update check, download, SHA-256 verification, installer prompt
- [ ] Uninstall leaves no VPN icon
- [ ] Battery: note % per hour idle with Nivyx on vs off (Settings → Battery)
- [ ] RAM: `adb shell dumpsys meminfo app.nivyx.android` with the UI closed
