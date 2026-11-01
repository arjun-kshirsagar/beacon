// Package peer implements the BitTorrent peer wire protocol (BEP 3): the
// handshake, length-prefixed messages, and bitfields.
//
// Everything read from a peer is bounded before it is allocated.
package peer
