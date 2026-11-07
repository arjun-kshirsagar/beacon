# Attack lab

Every attack in [VISION.md](VISION.md#4-security), how to reproduce it, the
defense, and the evidence that the defense holds. There are two kinds of
evidence:

- **Testbed runs.** `testbed/run.sh` starts honest Beacon nodes and an attacker
  in Docker, runs each attack with the real `beacon` and `attacker` binaries
  over real sockets, and checks the outcome.
- **Go tests.** Each defense also has unit or in-process tests that run with
  `go test ./...`, so a regression fails the build without Docker.

## Safety

The attack tools in `cmd/attacker` exist only for this lab, and three things
keep them in it:

1. **They refuse to run outside the testbed.** Nothing happens unless
   `BEACON_TESTBED=1` is set; only the testbed image sets it.
2. **They only target lab addresses.** Every target must resolve to a
   loopback or private address (RFC 1918 or IPv6 ULA); public addresses, and
   names that resolve to them, are refused before a packet is sent. The Sybil
   nodes answer only lab addresses. The tools never contact trackers or DHT
   routers on their own.
3. **The network is sealed.** The testbed network is `internal: true`: its
   containers have no route to the internet.

Floods are capped in the tools themselves (64 connections, 5000 messages per
connection, 5000 mesh packets). They are big enough to show a limit working,
and nothing more.

## Running it

Docker must be running. From the repository root:

```bash
testbed/run.sh              # build, then run every scenario
testbed/run.sh poison       # one scenario
testbed/run.sh down         # remove the testbed
```

Each scenario prints a PASS or FAIL line per check, and leaves the logs of its
last run in `testbed/logs/`.

The testbed's addresses:

| Container | Address | Role |
|---|---|---|
| `seed` | 10.88.1.10 | honest seeder of an 8 MB test file |
| `victim` | 10.88.1.20 | honest downloader |
| `dht` | 10.88.1.30 | honest DHT node (`beacon dht`) |
| `alice`, `bob`, `carol` | 10.88.1.40–42 | mesh chat nodes in a line; `bob` relays |
| `attacker` | 10.88.66.10 | the attacker, in its own /24 |

Last full run: 7 scenarios, 20 checks, all passed (2026-11-06).

## Piece poisoning

**Attack.** `attacker poison` claims to have every piece of the test torrent
and answers every block request with random bytes. The victim is given the
attacker as its first peer and an honest seeder as its second.

**Defense.** Every piece is checked against its SHA-1 from the info dictionary
before it is written or shared. Each block is attributed to the peer that
sent it. If a piece fails and one peer sent all of it, that peer is banned at
once; if several did, each is suspected, and once the piece later verifies,
whoever sent a block that differs from the verified data is banned ("smart
ban"). Bans are shared across torrents, expire after an hour and double for
repeat offenders.

**Evidence.**

- Testbed (`testbed/run.sh poison`): the victim logged
  `piece failed hash check piece=27 senders=[10.88.66.10]` then
  `banning peer peer=10.88.66.10 reason="bad piece"`, and finished with a file
  identical to the original.
- Go tests: `core/engine` `TestPoisonedPeerIsDropped`, `TestSmartBan`,
  `TestSharedReputationAcrossTorrents`; `core/reputation` `TestEvents`,
  `TestBanExpiryAndEscalation`.

## Connection and message flooding

**Attack.** `attacker flood` opens 32 connections to a seeder from one address
and sends 3,000 control messages down each, while an honest peer downloads
from the same seeder.

**Defense.** At most 2 connections per IP address; the rest are closed after
the handshake. Control messages are rate-limited per connection (200 a second
after a burst); a peer over the limit is disconnected and its reputation
lowered, and two offences ban it, after which it is refused at the handshake.
The dial queue and known-peer set are capped.

**Evidence.**

- Testbed (`testbed/run.sh flood`): the attacker reported 31 of 32
  connections cut off (one wrote all its messages into socket buffers before
  the cut-off reached it); the seeder logged `banning peer
  peer=10.88.66.10 reason=flood`; the honest download completed and matched.
- Go tests: `core/engine` `TestPerIPLimit`,
  `TestFloodAndViolationsAffectReputation`, `TestQueueCap`; the
  `FuzzPeerConn` fuzz target.

## Bad metadata for a magnet link

**Attack.** `attacker badmeta` answers BEP 9 metadata requests for the test
torrent with random bytes of the right size. A second instance
(`-oversize`) advertises metadata larger than clients accept.

**Defense.** Metadata is assembled only up to 16 MiB, refused if advertised
larger, and used only if its SHA-1 equals the info-hash in the magnet link.
Other peers are tried in parallel.

**Evidence.**

- Testbed (`testbed/run.sh badmeta`): the victim logged
  `metadata does not match info-hash` for the first attacker and
  `peer cannot serve metadata` for the oversized one, then fetched the real
  metadata from the seeder and completed the download.
- Go tests: `core/engine` `TestFetchMetadata`,
  `TestMetadataLargerThanOnePiece`; `core/peer` `FuzzExtension`.

## DHT Sybil and eclipse

**Attack.** `attacker sybil` runs 32 DHT nodes on one address, in its own
/24. Each answers every lookup with eight Sybils whose IDs match the lookup
target in the first 18 bytes, closer than any honest node can be, and never
returns peers. The victim's only way into the DHT is two Sybils and one
honest node; its magnet link has no trackers and no peers.

**Defense.** A lookup takes at most two candidates from any one /24, and
routing table buckets hold at most two nodes per /24, so however close the
Sybils claim to be, honest nodes elsewhere stay in the lookup. Incoming
queries are rate-limited per IP. Peers from the DHT are dialed only after
manual, tracker and local peers, and must still pass the info-hash handshake
and piece hashes.

**Evidence.**

- Testbed (`testbed/run.sh sybil`): the Sybils answered 22 queries from the
  victim, and the victim still reached the honest DHT node, found the seed
  (`DHT answered peers=1`) and completed the download.
- Go tests: `core/dht` `TestLookupSubnetCap` (with the cap removed, all 20
  Sybils were queried and the lookup was eclipsed), `TestQueryRateLimit`;
  `core/engine` `TestDialPriority`, `TestAcceptAddr`.

## Malformed .torrent files

**Attack.** `attacker badtorrents` writes 13 malformed files: 100,000 levels
of nesting, a 999,999,999,999-byte string length, an integer too large for 64
bits, a non-canonical integer, duplicate keys, trailing data, truncation, a
negative length, a zero piece length, a piece count that does not match the
length, and three unsafe paths (`..`, an empty component, a name of
`../etc`).

**Defense.** The bencode decoder bounds nesting (64 levels), checks every
length against the remaining input before allocating, rejects non-canonical
integers, duplicate keys and trailing data, and returns errors rather than
panicking. The metainfo parser checks lengths, piece counts and every path
component, and storage opens files through `os.Root`, so even a path that
slipped through could not leave the download directory.

**Evidence.**

- Testbed (`testbed/run.sh badtorrents`): `beacon info` rejected all 13 with
  an error and no crash, for example `bencode: nesting too deep`,
  `bencode: syntax error: duplicate key "length"` and
  `torrent: invalid metainfo: unsafe path component ".."`.
- Go tests and fuzzing: `core/bencode` `FuzzDecode`, `core/torrent`
  `FuzzParse`, `FuzzParseMagnet`, `TestParseInvalid`, run for hours in Phase 3.

Keys out of order are accepted on purpose: the info-hash covers the raw
bytes, so order cannot change what a torrent means, and real torrents
sometimes have unsorted keys.

## Mesh flooding

**Attack.** `attacker meshflood` links to the relay `bob` and sends 5,000
validly signed channel messages, each from a new random sender ID, so no
per-sender limit ever sees the same sender twice.

**Defense.** Each link accepts 50 packets a second after a burst of 512
(enough for a neighbour's store-and-forward flush); the rest are dropped at
the first hop. Messages from senders with no announce are held, not shown,
in bounded queues (8 per sender, 64 senders, 1 minute). Relays forward each
packet at most 8 times and queue at most 512 packets per link. TTL caps
every packet at 7 hops.

**Evidence.**

- Testbed (`testbed/run.sh meshflood`): the attacker sent 5,000 packets in
  about 100 ms. The relay's `/stats` showed `rate-limited 4483` and
  `relayed 520` (the burst). Carol displayed none of the flood, and Alice's
  "hello during the flood" still reached Carol through the relay.
- Go tests: `core/mesh` `TestLinkFlood`, `TestDuplicatesAndReplays`,
  `TestTTLLimitsHops`, and the flood step of `TestSimulatedMesh` (100 nodes);
  the `FuzzNode` fuzz target.

## Impersonation

**Attack.** `attacker impersonate` links to the relay, waits for a channel
message from Alice, and then tries to pass for her four ways: (1) announces
its own keys under the nickname "alice" and posts as her, (2) re-sends her
message with the text changed and a new packet ID under her original
signature, (3) replays her message unchanged, (4) announces its own keys
under her sender ID and posts from it.

**Defense.** Identity is a fingerprint (the SHA-256 of an Ed25519 key), not a
nickname. Signatures cover every byte of a packet except the TTL. Duplicates
are filtered by sender ID and packet ID. A sender ID stays bound to the first
key announced for it while that key is live. Interfaces tag a nickname with
the start of its fingerprint whenever two people nearby use it, and direct
messages to an ambiguous nickname are refused until a fingerprint is given.

**Evidence.**

- Testbed (`testbed/run.sh impersonate`): Carol saw
  `alice: the real alice here` and `alice#7e54: this is alice, trust me`. Her
  `/peers` listed two "alice"s with different fingerprints (`c62b…` and
  `7e54…`). The changed text and the post from the hijacked ID never
  appeared. The relay's `/stats` showed `bad signatures 3` (the altered
  message, the hijacking announce and its post) and `duplicates 1` (the
  replay).
- Go tests: `core/mesh` `TestSignature`, `TestSignaturesAndPending`,
  `TestDuplicatesAndReplays`, `TestIdentityProof`; `cmd/beacon`
  `TestTagIfShared`; the Android `ModelTest.tagsSharedNicknames`.

The tag only helps when the real person is nearby too. When they are not, a
lookalike shows under the plain nickname, so people should check fingerprints
(or scan the QR code) before trusting a name.

## Fake file announcements

**Attack.** A device announces files on the mesh that it does not have, and
never sends an offer (or sends one that leads nowhere), to waste requesters'
time.

**Defense.** A requester that gets no offer within 30 seconds, or whose
transfer fails because of the offer, forgets that announcer's share of the
file and moves to the next announcer. After 3 such strikes within an hour,
every share from that fingerprint is ignored until an hour passes without a
new strike. Shares are signed, so the strikes land on the right identity, and
fetched data is still checked piece by piece.

**Evidence.**

- Go test: `core/offline` `TestFakeAnnouncements` (three undelivered files,
  then the announcer's fourth share is ignored while an honest share stays
  listed); also `TestOffersOnlyFromWhoWasAsked`.
- Not in the Docker testbed: offline sharing needs Wi-Fi Direct, which
  containers do not have. It belongs in the phone test listed in
  [TODO.md](TODO.md).

## Known limits

- **Duplicate-link closing can be abused.** The TTL is not signed, so a device
  in radio range can replay a neighbour's announce with TTL 7 and get that
  neighbour's real link closed. This is capped at once per neighbour per
  minute; a signed link handshake would close the gap and needs a wire
  format change.
- **The first hop's burst is relayed.** Up to 512 flood packets get past the
  first relay before its rate limit applies, and travel on. They are held,
  unshown, by the next nodes until they expire.
- **A tiny DHT.** The testbed DHT has two honest nodes, which shows that the
  per-/24 cap keeps them reachable, but not how lookups behave in a large
  network under a larger Sybil population.
