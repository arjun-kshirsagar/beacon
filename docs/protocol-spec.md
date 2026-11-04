# Beacon mesh protocol

This document defines the bytes Beacon nodes exchange over the mesh. The Go
implementation lives in `core/mesh` and `core/noise`; any other implementation
(the Kotlin side included) must follow this document and the test vectors.

All integers are big-endian unless stated otherwise. Protocol version: **1**.

## Links and framing

The mesh runs over *links*: connections to a neighbouring device that carry
small frames whole and in order, or not at all (for example a BLE GATT
connection). Each link has an MTU, the largest frame it carries; the mesh
requires an MTU of at least 20 bytes.

A packet larger than the MTU is split into frames. Every frame starts with one
header byte:

| Bit | Meaning |
|---|---|
| `0x01` | start: first frame of a packet |
| `0x02` | end: last frame of a packet |

A packet that fits in one frame has header `0x03`. Other bits must be zero.
The receiver appends each frame's data to the packet in progress and hands the
packet on when it sees the end bit. If a start frame arrives while a packet is
in progress, the partial packet is discarded (its tail was lost). Frames
without the start bit and no packet in progress are discarded. A packet in
progress larger than `MaxPacket` is discarded.

**Keepalives.** A frame holding only the header `0x03` is an empty packet:
receivers rebuild nothing from it. A node sends one on any link it has sent
nothing on for 5 seconds, always between packets, and closes a link it has
received nothing on for 15 seconds. This drops a neighbour whose app has died
while its radio connection stayed up. Implementations without keepalives can
still link, but their links close whenever they are idle for 15 seconds.

**Duplicate links.** Only a packet's originator sends it with TTL 7, so a
validly signed announce that arrives with TTL 7 names the device at the other
end of that link. When two links lead to the same fingerprint, the node closes
the older one. This happens when a BLE device changes its advertised address
and a neighbour connects to it again. The TTL is not signed, so a device on
another link can replay a neighbour's announce with TTL 7 and pass for it. A
node therefore closes at most one duplicate link per neighbour per minute,
which bounds how often such a replay can cut the real link. The real
neighbour's next link is newer than the impostor's, so the impostor's is the
one closed next time.

### BLE links

Every Beacon device runs a GATT server with one service and advertises it.

| Item | Value |
|---|---|
| Service UUID | `6b1e0001-4c1a-4b8e-9f3d-be7ac0b3e500` |
| Frames characteristic | `6b1e0002-4c1a-4b8e-9f3d-be7ac0b3e500`, properties write, write without response, notify |
| Client configuration descriptor | `00002902-0000-1000-8000-00805f9b34fb` |

The advertisement carries the service UUID. The scan response carries service
data for the service UUID: an 8-byte random **instance**. Instances pair up
connections only; a device picks a new one, and restarts advertising, every 15
minutes, so the instance cannot be used to follow it for longer than the
platform's own address rotation allows.

For each pair of devices exactly one connects: the device whose instance is
lower (compared as bytes) acts as GATT client (central) and connects to the
other. The client then:

1. discovers services,
2. requests an ATT MTU of 517,
3. enables notifications on the frames characteristic.

The link is then up on both sides, with a frame size of the negotiated ATT MTU
minus 3 (the ATT header). The client sends frames by writing the
characteristic (write without response; write with response where that is
refused). The server sends frames as notifications. Each side has at most one
GATT operation in flight per connection, so frames go out in order. When the
connection drops, the link is down; the next scan result reconnects.

### LAN links

On a local network, nodes find each other with UDP multicast and link over
TCP. Every 5 seconds each node sends a **beacon** to `239.255.66.66:6766`:

| Size | Field |
|---|---|
| 4 | `BCN1` |
| 1 | version, `1` |
| 8 | instance: random per run, used only to pair up links |
| 2 | TCP port the node accepts links on |

A node hearing a beacon from an instance it has no link to connects to the
beacon's **source IP** and the advertised port; it never connects anywhere
else because of a beacon. Beacons are rate-limited to 30 a minute per source
IP, and a node redials the same instance at most every 10 seconds.

On a new TCP connection both sides immediately send a **hello**, and must
receive the other's within 5 seconds:

| Size | Field |
|---|---|
| 12 | `beacon-link` followed by a zero byte |
| 1 | version, `1` |
| 8 | sender's instance |

A connection to one's own instance is closed. If two nodes connect to each
other at once, both keep the connection dialed by the lower instance (compared
as bytes) and close the other.

After the hello, the connection carries link frames, each prefixed with its
length as a 2-byte big-endian integer. LAN links have an MTU of 8192 bytes, so
every packet fits in one frame. A frame of length 0 or over the MTU closes the
connection. A node keeps at most 16 LAN links and at most 2 unfinished
handshakes per remote IP.

## Packet

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version, `1` |
| 1 | 1 | type |
| 2 | 1 | TTL, 0–7 |
| 3 | 1 | flags |
| 4 | 8 | packet ID, random |
| 12 | 8 | timestamp, milliseconds since the Unix epoch |
| 20 | 8 | sender ID |
| 28 | 8 | recipient ID, only if flag `0x01` |
| … | 2 | payload length *n*, at most 4096 |
| … | *n* | payload |
| … | 64 | Ed25519 signature, only if flag `0x02` |

Flags:

| Bit | Meaning |
|---|---|
| `0x01` | recipient present (directed packet) |
| `0x02` | signature present |

Other bits must be zero. The largest packet (`MaxPacket`) is 4194 bytes.

Types:

| Type | Name | Recipient | Signed |
|---|---|---|---|
| `0x01` | announce | no | yes |
| `0x02` | channel message | no | yes |
| `0x03` | Noise handshake | yes | no |
| `0x04` | Noise transport (encrypted) | yes | no |
| `0x05` | file share | no | yes |

A packet whose recipient or signature flag does not match its type, whose TTL
is over 7, whose version or type is unknown, or whose length does not match
exactly is malformed and dropped.

**IDs.** Sender and recipient IDs are a node's *ephemeral* 8-byte ID. It is
random and changes periodically, so radio traffic cannot be linked to a person
over time; identity is proven by keys, never by IDs. Packet IDs are 8 random
bytes from a cryptographic source.

**Signature.** The Ed25519 signature covers the ASCII string `beacon-mesh-v1`
followed by a zero byte, then the packet from offset 0 through the end of the
payload with the TTL byte set to 0 and the signature flag set. Relays lower the
TTL, so it is excluded; everything else is covered.

## Relaying

A node receiving a packet:

1. Drops it if malformed, if the link has exceeded its rate limit, or if the
   timestamp is more than 15 minutes old or more than 5 minutes in the future.
2. If the pair (sender ID, packet ID) was seen recently, the packet is a
   duplicate and is not delivered again. Nodes keep a duplicate filter (two
   rotating Bloom filter generations with a secret hash seed). Flooding is
   asynchronous, so the first copy may have come along a long path with few
   hops left: nodes also remember the highest TTL each recent packet arrived
   with, and relay a duplicate (step 4) if its TTL is higher. A node therefore
   relays a packet at most 8 times.
3. Delivers it locally if it is a broadcast or addressed to one of the node's
   IDs.
4. If it is not addressed to this node and its TTL is above 0, sends it on all
   other links with the TTL lowered by one.

Originators send with TTL 7.

## Identity

Each device generates its own identity; there are no accounts.

- An **Ed25519** key pair signs broadcasts.
- An **X25519** key pair is the Noise static key for direct messages.
- The **fingerprint** is the lowercase hex SHA-256 of the Ed25519 public key.
  People verify each other by comparing fingerprints (or scanning them as QR
  codes).

## Payloads

### Announce (`0x01`)

| Size | Field |
|---|---|
| 32 | Ed25519 public key |
| 32 | X25519 Noise static public key |
| 1 | nickname length *n*, 1–32 |
| *n* | nickname, UTF-8 |

The packet is signed by the key it carries, which binds the Noise key and the
nickname to the fingerprint. Nicknames must be valid UTF-8 without control or
format characters (so a name cannot use, for example, right-to-left overrides
to imitate another).

A node announces when it starts, every 5 minutes, and whenever its ephemeral
ID changes. Receivers map the sender ID to the announced keys. A peer is
forgotten 20 minutes after its last announce. While an ID is bound to one
fingerprint, an announce from a different key for the same ID is ignored.

### Channel message (`0x02`)

| Size | Field |
|---|---|
| 1 | channel length *n*, 2–32 |
| *n* | channel: `#` followed by `a`–`z`, `0`–`9`, `-` or `_` |
| rest | text, UTF-8, 1–1024 bytes, no control characters except newline |

Channel messages are signed. A receiver verifies the signature against the
sender ID's announced key before delivering. A message from a sender ID with no
announce yet is held (up to 8 per sender, 64 senders, for 1 minute) and
delivered if the announce arrives. A relay that knows the sender's key drops a
message whose signature fails and does not relay it.

### File share (`0x05`)

| Size | Field |
|---|---|
| 20 | BitTorrent info-hash (BEP 3) |
| 8 | total size in bytes, 1 to 2^53 |
| 1 | name length *n*, 1–128 |
| *n* | name, UTF-8, no control characters, no `/` or `\`, not `.` or `..` |

A node sends a share to tell the mesh it can serve a file. Shares are signed
and handled like channel messages (held until the sender's announce arrives,
dropped if the signature fails). The info-hash commits to every piece, so the
name and size are only labels: a receiver verifies the content itself when it
fetches it (see "Offline file transfer").

Type `0x05` was added within version 1. Nodes from before it drop such
packets as malformed and do not relay them.

### Noise handshake (`0x03`)

| Size | Field |
|---|---|
| 1 | step: 1, 2 or 3 |
| rest | Noise handshake message |

Direct messages use `Noise_XX_25519_ChaChaPoly_SHA256` (Noise revision 34),
with the prologue `beacon-mesh-v1`. The initiator sends step 1 to the
recipient's current ID; replies go to the ID each message came from.

| Step | Noise message | Payload |
|---|---|---|
| 1 | `-> e` | empty |
| 2 | `<- e, ee, s, es` | identity proof of the responder |
| 3 | `-> s, se` | identity proof of the initiator |

The **identity proof** is the sender's Ed25519 public key (32 bytes) followed
by its signature over the ASCII string `beacon-noise-static-v1`, a zero byte,
and the sender's 32-byte X25519 static key. A receiver checks the signature
against the static key the handshake authenticated. The initiator also checks
that the proof's fingerprint is the one it meant to reach, and abandons the
handshake otherwise, before revealing its own identity in step 3. Payloads in
steps 2 and 3 are encrypted by Noise, so relays learn neither identity.

If both sides start a handshake at once, the side whose X25519 static key is
lower (compared as bytes) stays initiator and ignores the other's step 1; the
other side abandons its own handshake and responds. An unanswered handshake is
retried after 10 seconds, at most 3 times. Messages written before a session
exists wait (up to 32 per peer, 2 minutes) and are sent when it is set up.

### Encrypted message (`0x04`)

| Size | Field |
|---|---|
| 8 | nonce *n* |
| rest | ChaCha20-Poly1305 ciphertext with tag |

The ciphertext is produced with the sending key from the handshake's split
(the initiator's first key, the responder's second) and nonce *n*. Mesh
packets may be reordered or lost, so the nonce is sent explicitly rather than
counted by both sides. A sender uses each nonce once, counting from 0. A
receiver accepts a nonce once, and only if it is within 256 of the highest it
has accepted.

The associated data is the packet from offset 0 up to (not including) the
payload length, with the TTL byte set to 0. This binds the ciphertext to the
packet ID, timestamp, sender and recipient, so it cannot be replayed under a
fresh packet ID to get past duplicate filtering.

The plaintext is:

| Size | Field |
|---|---|
| 1 | kind: `0x01` text, `0x02` data |
| 2 | body length *n* |
| *n* | body |
| rest | zero padding |

A text body follows the rules for channel text. A data body is 1–1024
opaque bytes for a protocol layered on the mesh, such as the offline file
transfer messages below; it is never shown as a message.

The plaintext is padded to the smallest of 64, 128, 256, 512, 1024 or 2048
bytes that fits, so the ciphertext length reveals only a size class.

A new session with the same peer replaces the old one; the old one still
decrypts (but no longer encrypts) until the next replacement, so messages in
flight are not lost. A receiver that gets an encrypted message for which it has
no session (it restarted, say) starts a new handshake with the sender. That
message is lost; later ones get through.

## Offline file transfer

Devices with no internet share files by announcing them on the mesh and
moving the data with the BitTorrent engine over a local group network, such
as a Wi-Fi Direct group. Requests and offers are mesh **data** messages (kind
`0x02` inside an encrypted direct message), so only the two ends can read
them and each knows who the other is.

**Request** (`0x01`): asks a device that announced a file to let us fetch it.

| Size | Field |
|---|---|
| 1 | `0x01` |
| 20 | info-hash |

**Offer** (`0x02`): tells the requester how to reach the swarm.

| Size | Field |
|---|---|
| 1 | `0x02` |
| 20 | info-hash |
| 1 | network name length, 9–32 |
| … | network name: printable ASCII starting with `DIRECT-` |
| 1 | passphrase length, 8–63 |
| … | WPA2 passphrase: printable ASCII without spaces |
| 1 | peer count *n*, 1–16 |
| 6*n* | peers: IPv4 address (4 bytes) and TCP port (2 bytes), private addresses only |

The flow:

1. A device that shares a file seeds it and sends a share packet.
2. A device that wants the file sends a request to the announcer that
   announced it most recently, and to the next one if no offer arrives
   within 30 seconds.
3. The announcer answers only for files it has, and at most 10 requests a
   minute per asker. If it is in no group, it hosts one with a random network
   name and passphrase. It then offers its group, its own address and the
   addresses of the swarm peers it is connected to on the group's network.
4. The requester accepts an offer only from the device it asked. It joins the
   group, then connects only to offered peers in its own /24 on the group
   network, never elsewhere. It fetches the metadata (BEP 9) and the data,
   checking every piece against the info-hash.
5. Once complete, the requester seeds the file and sends its own share packet,
   so later requesters are pointed at it as well and fetch from several
   devices at once.

**Fake announcements.** If an announcer sends no offer within 30 seconds, or
its offer leads nowhere (no reachable peers, or the metadata or data cannot
be fetched), the requester forgets that announcer's share of the file and
counts a strike. After 3 strikes within an hour, every share from that
fingerprint is ignored until an hour passes without a new strike.

A device is in at most one group at a time; an offer for a different group
than the one it is in is declined. Anyone on the mesh can ask for an
announced file and so learn the group's credentials: joining a group gives
network access to its members, on which Beacon serves only the swarm.

## Store-and-forward

Every packet a node originates or relays is kept, once, for 10 minutes (at most 256
packets, oldest dropped first). When a new link comes up, the node first sends
its own latest announce, even if the store has dropped it, then every other
stored packet, oldest first. Duplicate filtering stops the
copies spreading further than new ground. This carries messages across gaps in
the mesh: a device that moves between groups delivers what it heard.

## Ephemeral IDs

A node picks a new random sender ID every 15 minutes and announces it, while
still accepting packets addressed to its previous ID for one more period. IDs
stop packet headers being linked over time. Announces carry the long-term
signing key, so any node in the mesh can still link a person's IDs to them;
rotation protects against passive tracking of packet headers, not against
mesh participants.

## Limits

| Limit | Value |
|---|---|
| Packets accepted per link | 50 per second, burst 512 (twice the store, so a neighbour's store-and-forward flush fits) |
| Packets accepted per sender ID | 20 per second, burst 100 |
| Packets queued for sending per link | 512, then dropped |
| Peers remembered | 1024, oldest evicted |

Sender IDs are free to invent, so the per-link limit is the real flood
defence: a flooding device is held to its own links' rates at the first hop.

There is no routing: directed packets (handshakes and encrypted messages) are
flooded like broadcasts and only their recipient acts on them. This costs
bandwidth but reveals nothing about who talks to whom beyond the IDs in the
header.

## Test vectors

`core/mesh/testdata/vectors.json` holds fixed encodings: an identity derived
from fixed private keys (bytes `00`–`3f`), its fingerprint and identity proof,
signed announce and channel packets, the channel packet split into frames for
a 23-byte MTU, a handshake packet, the associated data of an encrypted packet,
and a padded plaintext. `core/noise/testdata/cacophony_xx.json` holds the
Noise test vectors. Another implementation is compatible when it reproduces
both files.
