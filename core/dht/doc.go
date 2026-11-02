// Package dht implements the BitTorrent Mainline DHT (BEP 5), a Kademlia
// network that maps info-hashes to peers without a tracker.
//
// Defenses against a hostile network:
//   - Only nodes that answer a query or send us one enter the routing table;
//     addresses learned from "nodes" lists are only used for lookups.
//   - A bucket holds at most two nodes per /24, and full buckets keep their
//     long-lived nodes, which limits Sybil and eclipse attacks.
//   - Responses must come from the address queried, under a random transaction
//     ID, so off-path attackers cannot inject them.
//   - announce_peer requires a token bound to the sender's IP, and stored peers
//     are capped per info-hash and overall.
package dht
