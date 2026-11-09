# Using Beacon

## Desktop

`beacon <command> -h` prints a command's flags. `beacon version` prints the
version.

### Downloading: `beacon get`

```bash
beacon get ubuntu-26.04-desktop-amd64.iso.torrent
beacon get -o ~/Downloads "magnet:?xt=urn:btih:..."
```

Beacon seeds while it downloads, and exits when the download is complete and
every piece has been verified. Add `-seed` to keep seeding afterwards. A
partial download resumes from where it stopped.

Peers come from trackers, the DHT, peer exchange and other Beacon or
BitTorrent clients on your LAN (local peer discovery).

| Flag | Meaning |
|---|---|
| `-o dir` | download into `dir` (default: the current directory) |
| `-seed` | keep seeding after the download completes |
| `-peer host:port` | also connect to this peer (repeatable) |
| `-port n` | TCP port for peers and UDP port for the DHT (default 6881) |
| `-encryption prefer\|require\|off` | Message Stream Encryption (default `prefer`). It hides BitTorrent traffic from simple filters; it is not real security |
| `-no-dht` | do not use the DHT |
| `-no-lpd` | do not look for peers on the LAN |
| `-dht-bootstrap host:port` | join the DHT through this node instead of the public routers (repeatable) |
| `-allow-private` | accept private and LAN addresses from the DHT and peer exchange (for private networks) |
| `-v` | verbose logging |

Torrents marked private use their trackers only: no DHT, peer exchange or
local discovery.

### Sharing: `beacon create` and `beacon seed`

```bash
beacon create -o photos.torrent ./photos
beacon create -tracker udp://tracker.example.org:1337/announce -o iso.torrent big.iso
beacon seed -dir . photos.torrent
```

`create` prints the info-hash and a magnet link. `seed` checks the data in
`-dir` against the torrent before serving it, and takes the same network
flags as `get`. `beacon info file.torrent` shows what a torrent contains.

### A private DHT: `beacon dht`

```bash
beacon dht -port 6881
```

Runs a DHT node and nothing else. Other machines join it with
`-dht-bootstrap host:6881 -allow-private`, which makes a DHT that never
touches the public one.

### Chat: `beacon chat` and `beacon tui`

```bash
beacon chat -nick alice
beacon tui -nick alice
```

Both join the mesh on your local network: Beacon nodes find each other by
multicast and link over TCP, and messages hop from node to node. `tui` is the
full-screen version of `chat`.

| Flag | Meaning |
|---|---|
| `-nick name` | your nickname (default: your user name) |
| `-identity file` | where your identity keys live (created on first run; keep it private) |
| `-peer host:port` | link to this node directly (repeatable); needed where multicast does not work |
| `-no-discovery` | do not use multicast; link only to `-peer` |
| `-port n` | TCP port for mesh links (default: any free port) |
| `-o dir` | where downloaded shares are saved |
| `-dht` | also find peers for shared files through the internet DHT |
| `-log file`, `-v` | logging |

Commands inside chat:

| Command | Does |
|---|---|
| *text* | send to the current channel (`#general` at the start) |
| `/join #channel` | switch channel |
| `/msg name text` | encrypted direct message, to a nickname or fingerprint prefix |
| `/peers` | who is on the mesh, with their fingerprints |
| `/whoami` | your fingerprint |
| `/share path` | share a file or directory with the current channel |
| `/shares` | files shared with you |
| `/get n` or `/get magnet` | download a share; it is seeded afterwards |
| `/downloads` | download progress |
| `/stats` | mesh counters: links, relayed, duplicates, rate-limited, bad signatures |
| `/help`, `/quit` | help, leave |

If two people nearby use the same nickname, each is shown with the start of
their fingerprint (`alice#7e54`), and `/msg alice` asks you to pick one by
fingerprint. Channel messages are signed, so they cannot be forged, but they
are not encrypted. Direct messages are encrypted end to end.

## Android

Beacon needs Android 8.0 or later; offline file sharing needs Android 10 or
later. On first start, choose a nickname and allow Bluetooth (and, on
Android 12 and older, location, which Android requires for Bluetooth
scanning), nearby Wi-Fi devices and notifications.

Beacon keeps running in the background as a foreground service, with a
notification, so it can relay messages for others while the screen is off.
Some phones stop background apps anyway; if messages stop arriving, exempt
Beacon from battery optimisation in the system settings.

- **Nearby** lists people on the mesh with their fingerprints, your own
  fingerprint, and how many packets you relayed for others. Tap a
  person to message them. **Panic wipe** deletes your identity and every
  message on the phone.
- **Chat** holds channels and direct messages. Direct messages are end-to-end
  encrypted: phones that relay them cannot read them.
- **Files** shares files from your phone and lists files shared nearby. Tap
  **Get** and Beacon asks the phones that have the file to form a Wi-Fi Direct
  group, then fetches it from all of them at once, checking every piece.
  Received files are shared on to others.

Phones in range of each other link over Bluetooth by themselves; each phone
relays for the others, so people further away are reached in several hops.
Offline sharing works in airplane mode with Bluetooth and Wi-Fi turned back
on.

Desktop and Android both use the same mesh protocol, but they do not link
to each other yet: desktop uses the LAN and phones use Bluetooth.
