# Beacon

Peer-to-peer file sharing and chat that works over the internet and without it.

- **BitTorrent, from scratch.** A Go engine that speaks the real BitTorrent
  protocol: `.torrent` files and magnet links, HTTP and UDP trackers, the DHT,
  peer exchange, local peer discovery and Message Stream Encryption.
  Downloads and seeds alongside qBittorrent and Transmission.
- **A mesh for chat.** Devices relay signed messages to each other over
  Bluetooth LE (Android) or the local network (desktop), up to 7 hops, with
  Noise-encrypted direct messages. No servers or accounts are involved.
- **Offline file sharing.** Android phones find files over the mesh and fetch
  them from each other over Wi-Fi Direct, from several phones at once, with
  no internet connection.
- **Hardened.** Every parser is fuzzed, every piece is hash-checked, peers that
  misbehave are banned, and each attack Beacon defends against is reproduced
  in a sealed lab ([docs/attacks.md](docs/attacks.md)).

## Install

**Desktop (Linux, macOS, Windows).** Download the archive for your system from
[Releases](https://github.com/arjun-kshirsagar/beacon/releases), check it
against `checksums.txt`, and put `beacon` on your `PATH`:

```bash
sha256sum --ignore-missing -c checksums.txt
tar xzf beacon_*_linux_amd64.tar.gz
sudo install beacon /usr/local/bin/
```

Or build it with Go 1.27 or later:

```bash
go install github.com/arjun-kshirsagar/beacon/cmd/beacon@latest
```

**Android 8.0 or later.** Download `beacon-<version>.apk` from
[Releases](https://github.com/arjun-kshirsagar/beacon/releases) and install it
(allow installs from your browser or file manager when asked). Before
installing, you can check that the APK is signed with the Beacon release key:

```bash
apksigner verify --print-certs beacon-1.0.0.apk
```

The `SHA-256` digest it prints must be:

```
RELEASE-CERTIFICATE-SHA256 (filled in when the release key is created; see docs/RELEASING.md)
```

Offline file sharing needs Android 10 or later.

## Quick start

```bash
beacon get "magnet:?xt=urn:btih:..."          # download, seeding while it runs
beacon get -seed ubuntu-26.04-desktop-amd64.iso.torrent
beacon create -o photos.torrent ./photos      # make a torrent
beacon seed -dir . photos.torrent             # and seed it
beacon chat -nick alice                       # chat with Beacon users on your LAN
beacon tui -nick alice                        # the same, full screen
```

In chat, `/help` lists the commands: channels, encrypted direct messages
(`/msg`), sharing files with everyone nearby (`/share`, `/shares`, `/get`) and
`/peers` to see who is around and their fingerprints.

On Android, open the app and allow Bluetooth, nearby devices and
notifications. The **Nearby** tab shows who is in range, **Chat** holds
channels and direct messages, and **Files** shares and fetches files.

The full guide is in [docs/usage.md](docs/usage.md).

## Security

- Mesh messages are signed with Ed25519. Your identity is the fingerprint of
  your key, not your nickname: when two people nearby use the same nickname,
  Beacon shows each with the start of their fingerprint (`alice#7e54`).
  Compare fingerprints in person (the Nearby tab and `/peers` show them)
  before trusting a name.
- Direct messages use the Noise XX handshake (X25519, ChaCha20-Poly1305,
  SHA-256), with forward secrecy and replay protection.
- Channel messages are signed but **not encrypted**: anyone nearby can read
  them.
- Beacon does not hide who you are. Bluetooth activity is visible to people
  nearby, and internet peers see your IP address, as with any BitTorrent client.
- Messages are kept in memory only and are gone when Beacon stops. On
  Android, **Panic wipe** on the Nearby tab also deletes your identity keys.

Report vulnerabilities privately through GitHub's
[security advisories](https://github.com/arjun-kshirsagar/beacon/security/advisories/new),
not in public issues.

## Documentation

| Document | Contents |
|---|---|
| [docs/usage.md](docs/usage.md) | Every command, flag and Android screen |
| [docs/VISION.md](docs/VISION.md) | Design, goals and roadmap |
| [docs/protocol-spec.md](docs/protocol-spec.md) | Mesh packets, BLE service, handshakes and offline sharing on the wire |
| [docs/attacks.md](docs/attacks.md) | Each attack, its defense, and the evidence |
| [docs/RELEASING.md](docs/RELEASING.md) | How releases are built and signed |
| [docs/TODO.md](docs/TODO.md) | Known gaps and planned work |
| [AGENTS.md](AGENTS.md) | Repository layout, conventions and commands for contributors |

## Building from source

```bash
go build ./...        # everything
go test -race ./...   # all tests
make fuzz             # every fuzz target, one minute each
```

The Android app needs the Android SDK and NDK:

```bash
./scripts/build-aar.sh                      # the Go core as android/app/libs/core.aar
cd android && ./gradlew assembleDebug       # android/app/build/outputs/apk/debug/
```

Use legal content when testing against real swarms, such as Linux
distribution images.
