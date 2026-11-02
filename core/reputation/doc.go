// Package reputation scores peers by what they do and bans the ones that harm
// us.
//
// A peer is identified by a key, normally its IP address. Unambiguous evidence
// (being the only sender of a corrupt piece, or a block proven wrong once the
// piece verifies) bans at once. Ambiguous evidence (one of several senders of a
// corrupt piece, protocol violations, snubbing) lowers the score, and a good
// history of verified pieces buys an honest peer some slack. Bans expire, and
// each repeat ban lasts twice as long, so a reassigned NAT address recovers
// while a persistent attacker stays out.
package reputation
