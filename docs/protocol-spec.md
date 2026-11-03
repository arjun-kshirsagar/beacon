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
2. Drops it if the pair (sender ID, packet ID) was seen recently. Nodes keep a
   duplicate filter (two rotating Bloom filter generations with a secret hash
   seed).
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

## Store-and-forward

Every packet a node originates or relays is kept for 10 minutes (at most 256
packets, oldest dropped first). When a new link comes up, the node sends the
new neighbour every stored packet, oldest first. Duplicate filtering stops the
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
| Packets accepted per link | 50 per second, burst 200 |
| Packets accepted per sender ID | 20 per second, burst 100 |
| Packets queued for sending per link | 512, then dropped |
| Peers remembered | 1024, oldest evicted |

Sender IDs are free to invent, so the per-link limit is the real flood
defence: a flooding device is held to its own links' rates at the first hop.
