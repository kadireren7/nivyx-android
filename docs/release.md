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
`NIVYX_KEYSTORE_PASSWORD`, `NIVYX_KEY_ALIAS` exist. For a stable tag (no `-`) it **fails** without them instead of
publishing an unsigned APK, and it never overwrites a release that already exists: the canonical stable build is the
one created and verified by hand from the tagged commit.
Assets: `nivyx-android-vX.Y.Z.apk`, `SHA256SUMS`, `nivyx-android-vX.Y.Z.spdx.json`.
Version source of truth: `nivyx.version` in `gradle.properties` and `[workspace.package]` in `Cargo.toml`.

Supported: minSdk 21 (Android 5.0), targetSdk/compileSdk 36. ABIs: arm64-v8a, armeabi-v7a, x86_64.
Physically tested: one Android 16 tablet (rc1 build). Everything else is untested (see `device-test-plan.md`).
