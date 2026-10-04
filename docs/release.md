# Releasing & signing

Private keys are never committed. Signing reads environment variables only:
`NIVYX_KEYSTORE_FILE`, `NIVYX_KEYSTORE_PASSWORD`, `NIVYX_KEY_ALIAS`, optional `NIVYX_KEY_PASSWORD`.

```
./gradlew :app:assembleRelease          # signed if the variables are set, else app-release-unsigned.apk
```
**An unsigned APK cannot be installed.** To sign manually:
```
zipalign -p -f 4 app-release-unsigned.apk aligned.apk
apksigner sign --ks my.jks --out nivyx-android-vX.Y.Z.apk aligned.apk
apksigner verify nivyx-android-vX.Y.Z.apk
```
Keep the same key for every release: Android refuses updates signed with a different key.

CI (`.github/workflows/release.yml`) signs only when the repository secrets `NIVYX_KEYSTORE_B64`,
`NIVYX_KEYSTORE_PASSWORD`, `NIVYX_KEY_ALIAS` exist; otherwise it publishes the unsigned candidate.
Assets: `nivyx-android-vX.Y.Z.apk`, `SHA256SUMS`, `nivyx-android-vX.Y.Z.spdx.json`.
Version source of truth: `nivyx.version` in `gradle.properties` and `[workspace.package]` in `Cargo.toml`.

Supported: minSdk 21 (Android 5.0), targetSdk/compileSdk 36. ABIs: arm64-v8a, armeabi-v7a, x86_64.
Tested Android versions: **none on a device** (see `device-test-plan.md`).
