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
