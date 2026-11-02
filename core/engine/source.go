package engine

import (
	"math/bits"
	"strings"
)

// PeerSource is where a peer address came from. Sources form a bit set.
type PeerSource uint8

// Sources in increasing order of trust.
const (
	SourcePEX PeerSource = 1 << iota
	SourceDHT
	SourceLPD
	SourceTracker
	SourceManual
)

func (s PeerSource) String() string {
	var names []string
	for i, n := range []string{"pex", "dht", "lpd", "tracker", "manual"} {
		if s&(1<<i) != 0 {
			names = append(names, n)
		}
	}
	return strings.Join(names, "+")
}

// candidate is an address waiting to be dialed.
type candidate struct {
	addr    string
	sources PeerSource
}

// priority ranks a candidate by its most trusted source, and puts addresses
// that several independent sources agree on ahead of single-source ones of the
// same rank. A list of fake peers fed through one channel, such as PEX, is
// therefore dialed after everything better corroborated.
func (c *candidate) priority() int {
	p := 2 * bits.Len8(uint8(c.sources))
	if bits.OnesCount8(uint8(c.sources)) >= 2 {
		p++
	}
	return p
}
