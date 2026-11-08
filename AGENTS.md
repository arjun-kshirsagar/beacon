# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

Beacon is a peer-to-peer file-sharing and chat system that works over the internet
and offline. It has three parts:

1. A from-scratch **BitTorrent engine** in Go, interoperable with the real BitTorrent network.
2. A **Bluetooth LE mesh** for chat, with Noise-encrypted direct messages.
3. **Offline file sharing**: the torrent engine running over BLE (discovery) and
   Wi-Fi Direct (bulk transfer) between Android phones.

Security (fuzzing, peer reputation, an attack lab) runs through all of it.
Full design: [docs/VISION.md](docs/VISION.md).

## Repository layout

One monorepo. Go lives at the root; the Android app is a standalone Gradle project in
`android/`. Some directories below are planned and may not exist yet.

```
go.mod              module github.com/arjun-kshirsagar/beacon
core/               all protocol logic — pure Go, no platform code
  bencode/          BitTorrent encoding (BEP 3)
  torrent/          .torrent parsing, info-hash
  peer/             peer wire protocol
  tracker/          HTTP (BEP 3/23) and UDP (BEP 15) trackers
  dht/              Kademlia DHT (BEP 5)
  lpd/              local peer discovery over multicast (BEP 14)
  lan/              LAN mesh links: multicast beacons, TCP links
  engine/           piece picker, choking, endgame, storage
  mse/              BitTorrent Message Stream Encryption (obfuscation, not security)
  mesh/             mesh packets, TTL, dedup, fragmentation, store-and-forward
  offline/          offline file sharing: mesh announcements, group offers, swarms
  noise/            Noise XX handshake
  reputation/       peer scoring and banning
  transport/        Transport interface, TCP/UDP, in-memory fake for tests
mobile/             narrow gomobile-facing API for Android
cmd/beacon/         desktop CLI
cmd/attacker/       attack-lab tools (testbed only)
testbed/            Docker Compose attack testbed
android/            Kotlin app: BLE + Wi-Fi Direct transports, Compose UI
docs/               VISION.md, protocol-spec.md, attacks.md
```

## Commands

```bash
go build ./...                 # build everything
go test ./...                  # run all tests
go test -race ./...            # tests with the race detector
go vet ./...                   # static checks
go test ./core/<pkg> -run '^$' -fuzz <FuzzName> -fuzztime 30s   # fuzz a parser
govulncheck ./...              # known-vulnerability scan
make snapshot                  # release archives into dist/, nothing published
```

Android (from `android/`):

```bash
./scripts/build-aar.sh    # gomobile bind ./mobile into android/app/libs/core.aar; run from repo root
./gradlew assembleDebug
./gradlew test
```

## Architecture rules

- **`core/` is platform-independent.** No Android, OS-specific, or UI code in `core/`.
- **Everything network-facing goes through the `Transport` interface.** Core packages
  send and receive bytes; they never open sockets or radios directly. This keeps the
  engine identical on desktop and Android and lets tests run a simulated mesh in-process.
- **`mobile/` is the only package gomobile binds.** Keep its API narrow: strings,
  numbers, `[]byte`, and interfaces built from those. Convert to richer core types
  inside `mobile/`.
- **Android code only handles platform concerns**: BLE, Wi-Fi Direct, UI, the foreground
  service, Keystore. Protocol logic belongs in Go.

## Go conventions

- Go 1.27+. Format with `gofmt`; code must pass `go vet`.
- Prefer the standard library. Add dependencies only when clearly justified
  (`golang.org/x/crypto` is expected; others need a reason).
- Return errors, don't panic, especially on any input from the network or disk.
  Wrap with `fmt.Errorf("...: %w", err)` and define sentinel errors with `errors.New`
  where callers need to distinguish cases.
- Use `context.Context` for cancellation in anything long-running or network-bound.
- Use `log/slog` for logging.
- Table-driven tests. Every parser gets a fuzz target with seed inputs in `testdata/`.
- Tests that need peers use the in-memory transport, not real sockets.

## Security rules

- **Treat all peer input as hostile.** Bound every length, count and allocation before
  using it. Never allocate based on an unchecked length prefix.
- Verify every torrent piece hash before writing or sharing it.
- Use only `crypto/*` and `golang.org/x/crypto` primitives. Don't invent cryptography.
  Noise must follow the spec and be checked against its test vectors.
- Use `crypto/rand` for keys, nonces and IDs, never `math/rand`.
- **Attack tools in `cmd/attacker/` run only against the local testbed.** Never point
  them at public trackers, the public DHT, or real swarms.
- Never commit secrets: signing keystores, API keys, private keys.

## Protocol changes

The mesh packet format, BLE service/characteristic UUIDs, and handshake details are
defined in `docs/protocol-spec.md`. Any change to wire formats must:

1. Update `docs/protocol-spec.md` in the same commit.
2. Bump or respect the protocol version byte.
3. Update the shared test vectors so Go and Kotlin stay compatible.

## Testing against real networks

Use legal content only, such as Linux distribution ISOs. For local interoperability
tests, run qBittorrent or Transmission as a peer. BLE testing requires physical
Android devices; the emulator cannot talk to real hardware.

## Commits

- Small, focused commits with imperative messages (`bencode: reject leading zeros in integers`).
- Prefix with the package or area: `bencode:`, `dht:`, `mesh:`, `android:`, `docs:`.
- `go test ./...` must pass before committing.
