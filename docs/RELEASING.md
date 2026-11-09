# Releasing

A release is a version tag. Pushing `vX.Y.Z` runs
[.github/workflows/release.yml](../.github/workflows/release.yml), which:

1. runs the tests, then builds `beacon` for Linux, macOS and Windows (amd64
   and arm64) with GoReleaser ([.goreleaser.yaml](../.goreleaser.yaml)), and
   makes a **draft** GitHub release with the archives, `checksums.txt` and a
   changelog from the commit messages;
2. builds the Go core for Android, runs the Android unit tests, builds the
   release APK with `versionName` X.Y.Z and `versionCode`
   X×10000 + Y×100 + Z, signs it with the release key, checks the signature
   with `apksigner`, and attaches `beacon-X.Y.Z.apk` and its SHA-256 to the
   draft;
3. publishes the release once both have succeeded. If either fails, the
   release stays a draft and nothing is published.

`cmd/attacker` is never built or shipped.

## One-time setup: the release key

Android only installs an update if it is signed with the same key as the
installed app, so this key must exist once, for every release, forever. If it
is lost, users must uninstall Beacon (and lose its identity keys) to install
a new version. If it leaks, anyone can ship an "update" that Android accepts.

1. Create it **outside the repository**, and keep a backup offline:

   ```bash
   keytool -genkeypair -keystore ~/beacon-release.jks -alias beacon \
     -keyalg EC -groupname secp256r1 -validity 10000 \
     -dname "CN=Beacon"
   ```

   Use a long, random store password; `keytool` asks for it. With a PKCS12
   keystore (the default) the key password is the same as the store
   password.

2. Put the certificate's SHA-256 fingerprint in the README, so people can
   check the APK:

   ```bash
   keytool -list -v -keystore ~/beacon-release.jks -alias beacon | grep SHA256
   ```

   Copy it without colons, in lower case, as `apksigner` prints it.

3. Add the key to GitHub as secrets of an environment named `release`
   (Settings → Environments → New environment). The `android` job is the only
   job that uses that environment, so no other workflow can read the key.
   Restrict the environment to tags matching `v*`:

   ```bash
   gh api -X PUT repos/arjun-kshirsagar/beacon/environments/release
   base64 -i ~/beacon-release.jks | gh secret set BEACON_KEYSTORE_BASE64 --env release
   gh secret set BEACON_KEYSTORE_PASSWORD --env release   # prompts for the value
   gh secret set BEACON_KEY_PASSWORD --env release        # the same password
   gh secret set BEACON_KEY_ALIAS --env release --body beacon
   ```

The keystore, its passwords and `android/keystore.properties` must never be
committed; `.gitignore` excludes `*.jks`, `*.keystore`, `*.p12` and
`keystore.properties`.

## Cutting a release

1. Make sure `main` is green in CI and `docs/TODO.md` says what is still
   missing.
2. Tag and push:

   ```bash
   git tag -a v1.0.0 -m "Beacon 1.0.0"
   git push origin v1.0.0
   ```

3. Watch the `release` workflow (`gh run watch`). When it finishes, the
   release is public at
   https://github.com/arjun-kshirsagar/beacon/releases.
4. Check the published APK's certificate against the README:

   ```bash
   gh release download v1.0.0 -p 'beacon-*.apk'
   apksigner verify --print-certs beacon-1.0.0.apk
   ```

Tags with a suffix (`v1.1.0-rc.1`) are published as pre-releases.

## Building a release locally

Desktop, without publishing anything:

```bash
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean
ls dist/
```

A signed APK, with the key described in an untracked
`android/keystore.properties`:

```properties
storeFile=/Users/you/beacon-release.jks
storePassword=...
keyAlias=beacon
keyPassword=...
```

```bash
./scripts/build-aar.sh
cd android && ./gradlew assembleRelease -PversionName=1.0.0 -PversionCode=10000
```

The same values can come from the environment instead: `BEACON_KEYSTORE`,
`BEACON_KEYSTORE_PASSWORD`, `BEACON_KEY_ALIAS`, `BEACON_KEY_PASSWORD`.
Without either, `assembleRelease` produces an unsigned APK, which Android will
not install.
