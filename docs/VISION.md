# Beacon — Vision

> Peer-to-peer file sharing and chat that works over the internet **and** with no
> internet at all, by passing data phone to phone over Bluetooth and Wi-Fi Direct —
> built from scratch and hardened against attacks.

## The problem

File sharing and messaging depend on infrastructure — cell towers, routers, central
servers. That infrastructure fails or is taken away:

- **Disasters** knock out towers.
- **Crowds** (festivals, stadiums, protests) overload networks.
- **Censorship** shuts the internet down.
- **Remote places** — villages, ships, planes — never had it.

Existing tools each solve part of the problem:

| Tool | Strength | Gap |
|---|---|---|
| BitTorrent clients | Fast, verified, scalable file distribution | Need the internet |
| Mesh chat (bitchat, Briar) | Work offline | Text only, not built for large files |
| Offline file-transfer apps | Work offline | One-to-one, no content verification, no swarming |

**Beacon combines them**: BitTorrent's tamper-proof, swarm-based distribution running
over an offline phone mesh, with end-to-end encrypted chat built in.

## Pillars

### 1. BitTorrent engine

A complete BitTorrent client written from scratch in Go, interoperable with the real
BitTorrent network (qBittorrent, Transmission, etc.).

| Feature | Spec |
|---|---|
| Bencode, `.torrent` parsing, info-hash | BEP 3 |
| HTTP trackers (compact peer lists) | BEP 3, BEP 23 |
| UDP trackers | BEP 15 |
| Peer wire protocol, piece verification | BEP 3 |
| Rarest-first selection, endgame, choking / tit-for-tat | BEP 3 |
| Multi-file torrents, resume | BEP 3 |
| Extension protocol | BEP 10 |
| Magnet links / metadata exchange | BEP 9 |
| DHT (Kademlia) | BEP 5 |
| Local peer discovery | BEP 14 |
| Peer exchange (optional) | BEP 11 |

**Milestone:** download an Ubuntu ISO from a magnet link using only the DHT, verify
it, and seed it back.

### 2. Mesh network and chat

A Bluetooth LE mesh where every phone advertises and scans at the same time, connects
to nearby phones, and relays messages for others.

```
 You ──BLE──► Phone B ──BLE──► Phone C ──BLE──► Friend
      ~30 m           ~30 m            ~30 m
```

- **Relaying** with a hop limit (TTL, max 7).
- **Duplicate suppression** via message IDs and a Bloom filter.
- **Fragmentation** to fit BLE's small packets (~185–512 bytes).
- **Store-and-forward** for recipients not currently reachable.
- **Public channels** (`#general`) broadcast through the mesh.
- **Private DMs**, end-to-end encrypted — relays cannot read them.
- **No accounts**: identity is an Ed25519 key pair generated on the device;
  peers verify each other by fingerprint or QR code.

**Encryption:** Noise XX handshake (X25519, ChaCha20-Poly1305, SHA-256) for forward
secrecy; Ed25519 signatures on broadcasts.

**Milestone:** three phones in a line (A and C out of range of each other) exchange
encrypted DMs relayed through B, and B cannot read them.

### 3. Offline file sharing

The torrent engine running over the mesh — this is what makes Beacon different.

| Radio | Speed | Role |
|---|---|---|
| Bluetooth LE | ~10–50 KB/s | Discovery: announce info-hashes, chat |
| Wi-Fi Direct | ~10–30 MB/s | Bulk transfer of pieces, phone to phone |

Flow:

1. Alice shares a file; Beacon creates a torrent and announces its info-hash over BLE.
2. Bob taps **Get**; the phones form a Wi-Fi Direct link.
3. The engine transfers pieces and verifies each hash.
4. Bob seeds automatically — Carol can now pull from Alice **and** Bob.

**Bridging:** a phone with internet can download from the global swarm and re-share
to offline phones nearby at the same time.

| Situation | Transport |
|---|---|
| Internet available | TCP / UDP — global swarm |
| Same Wi-Fi, no internet | Local peer discovery + TCP |
| No Wi-Fi at all | BLE discovery + Wi-Fi Direct |

**Milestone:** three phones in airplane mode (Bluetooth and Wi-Fi on) share a 50 MB
file, with Carol receiving pieces from both Alice and Bob.

### 4. Security

Security is built into every layer, then demonstrated in an attack lab.

**Defenses**

| Defense | Protects against |
|---|---|
| Fuzz-tested parsers (bencode, peer wire, mesh packets, Noise) | Crashes and exploits from crafted input |
| Strict limits on message size, connections, rates | Resource exhaustion |
| Per-block peer attribution and reputation | Piece poisoning |
| DHT routing-table diversity and per-subnet limits | Sybil and eclipse attacks |
| Cross-checking tracker, DHT and PEX results | Fake peer lists |
| Mesh rate limits and TTL caps | Flooding and battery drain |
| Signed mesh messages | Impersonation and tampering |
| Rotating ephemeral IDs | Physical tracking via Bluetooth |
| Message padding | Inference from message length |
| Panic wipe | Device seizure |

**Attack lab** — a Docker Compose testbed of Beacon nodes plus purpose-built attacker
nodes, on a private network only:

| Attack | Expected outcome |
|---|---|
| Piece poisoning | Detected by hash, attacker banned, download completes |
| DHT Sybil / eclipse | Victim still reaches honest peers |
| Connection / message flooding | Limits hold, node stays responsive |
| Malformed `.torrent` | Rejected safely |
| Mesh flooding | Rate-limited, relays stay healthy |
| Fake file announcements | Ignored after failed fetches |
| Impersonation | Signature check fails |

Each attack is documented in `docs/attacks.md` with reproduction steps, the defense,
and test evidence.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                          GO CORE                             │
│  Torrent engine + DHT │ Mesh │ Noise crypto │ Reputation     │
│                    Transport interface                       │
├──────────────────────────────┬───────────────────────────────┤
│  Desktop (Go)                │  Android (Kotlin)             │
│  • TCP / UDP                 │  • BLE transport              │
│  • Local peer discovery      │  • Wi-Fi Direct transport     │
│  • CLI + TUI                 │  • Jetpack Compose UI         │
│                              │  • Foreground service         │
│                              │  ◄── gomobile (.aar) ──►      │
└──────────────────────────────┴───────────────────────────────┘
```

The core never knows which radio it is using. It sends bytes through a `Transport`
interface, so the same engine runs on laptops and phones, and a 100-node mesh can be
simulated in-process with a fake transport.

## Tech stack

| Layer | Technology |
|---|---|
| Core | Go (stdlib + `golang.org/x/crypto`) |
| Android | Kotlin, Jetpack Compose, coroutines |
| Go ↔ Android bridge | gomobile → `.aar` |
| Bluetooth | `android.bluetooth.le` |
| Bulk transfer | Wi-Fi Direct (`WifiP2pManager`) |
| Crypto | X25519, Ed25519, ChaCha20-Poly1305, SHA-1 / SHA-256, Noise XX |
| Desktop UI | `cobra` CLI, `bubbletea` TUI |
| Security tooling | `go test -fuzz`, `-race`, `govulncheck`, `staticcheck`, `gosec` |
| Attack testbed | Docker Compose, `toxiproxy` / `tc netem` |
| Debugging | Wireshark, nRF Connect, `pprof` |
| CI / releases | GitHub Actions, GoReleaser, signed APK |

## How people use it

**Desktop** — a single binary:

```
beacon get ubuntu.torrent
beacon get "magnet:?xt=urn:btih:..."
beacon seed ./photos
beacon chat --lan
beacon tui
```

**Android** — an app with three tabs:

- **Nearby** — people and channels around you, hop counts, verification status.
- **Chat** — public channels and encrypted DMs.
- **Files** — files available nearby, downloads, what you're seeding.

**Developers** — importable Go packages (`core/bencode`, `core/engine`, …).

## Roadmap

| Phase | Scope | Done when |
|---|---|---|
| 0 | Go fundamentals | Comfortable with slices, structs, errors, interfaces |
| 1 | Bencode → `.torrent` → HTTP tracker → peer wire | An Ubuntu ISO downloads and verifies |
| 2 | Seeding, choking, rarest-first, endgame, multi-file, resume, UDP trackers, magnet, DHT | A magnet link downloads with no tracker |
| 3 | Fuzzing, limits, peer reputation | Fuzzers run clean for hours |
| 4 | Mesh core: packets, TTL, dedup, fragmentation, store-and-forward, Noise, identity | A simulated 100-node mesh passes tests |
| 5 | Desktop LAN transport, local discovery, TUI | Two machines chat and share over LAN |
| 6 | Android: gomobile bridge, BLE transport, UI, foreground service | Three phones relay encrypted chat |
| 7 | Offline files: BLE announcements, Wi-Fi Direct, bridging | Phones in airplane mode share a 50 MB file |
| 8 | Attack lab and `docs/attacks.md` | Every attack demonstrated and defended |
| 9 | Release: GoReleaser, signed APK, docs | v1.0 on GitHub Releases |

Every phase ends in something that works on its own.

## Non-goals

- **iOS** — Android first; the protocol spec keeps the door open.
- **Anonymity** — traffic is encrypted, but Bluetooth activity is observable nearby
  and internet peers see IP addresses. Beacon is not Tor.
- **Global offline reach** — messages travel only as far as a chain of devices.
- **Message history** — messages stay in memory by design.
- **Piracy** — Beacon is a general distribution tool; test with legal content.

## Known hard parts

| Area | Why |
|---|---|
| Torrent concurrency | Many peers coordinating piece selection; easy to introduce races |
| DHT | Kademlia routing is the most complex single component |
| Android BLE | Vendor differences, `GATT_ERROR 133`, connection limits |
| Android background limits | Aggressive battery optimizers on some brands |
| Wi-Fi Direct | Slow connection setup, occasional user prompts |
| gomobile boundary | Only simple types cross it; the API must stay narrow |
| Noise XX | Easy to get subtly wrong; verify against test vectors |
