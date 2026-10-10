Nivyx Android 1.0.1, reliability patch.

* Fixed: pressing Start and Stop rapidly could leave the UI showing "Active" and the device without internet. Start, stop and restart are now executed by one serialized state machine (STOPPED, STARTING, RUNNING, STOPPING). Repeated or overlapping commands coalesce to the last requested state, and at most one VPN interface and one engine exist at any time.
* Any failure while starting tears the interface and engine down and returns to Stopped.
* Changing routes or excluded apps now restarts through the same state machine instead of a timed stop/start.
* Refreshed the emerald/mint/teal Android theme across the Start/Stop screen, status ring, buttons and notification.
* Physical-device verification of this build is recorded in docs/device-test-plan.md only after it has been done.
* Verify downloads with `SHA256SUMS`; SBOM attached.
