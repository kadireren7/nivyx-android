# Physical device test plan

Nothing below has been run. **Every box is unchecked until a person tests it on a real phone.**
Record device, Android version, ABI, carrier/ISP and result for each line.

- [ ] Clean install of the signed APK (also on an Android 5–7 and a 2 GB RAM device if available)
- [ ] Start → Android VPN consent dialog → notification appears → key icon shown
- [ ] Discord works (app + web)
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
