package engine

import (
	"net/netip"
	"slices"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
)

// pexInterval is how often we send each peer the changes to our peer list.
// BEP 11 asks for at most one message a minute. It is a variable for tests.
var pexInterval = time.Minute

// sendPEX tells every peer that supports ut_pex which peers we have connected
// to and disconnected from since our last message to it.
func (c *Client) sendPEX() {
	if c.t.Private {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current := map[string]*peerConn{}
	for pc := range c.conns {
		if pc.listenAddr != "" {
			current[pc.listenAddr] = pc
		}
	}
	for pc := range c.conns {
		if pc.extPEX == 0 {
			continue
		}
		var msg peer.PEX
		for _, addr := range sortedKeys(current) {
			if len(msg.Added) == peer.MaxPEXPeers {
				break
			}
			other := current[addr]
			ap, err := netip.ParseAddrPort(addr)
			if other == pc || pc.pexSent[addr] || err != nil {
				continue
			}
			msg.Added = append(msg.Added, ap)
			msg.Flags = append(msg.Flags, c.pexFlags(other))
			pc.pexSent[addr] = true
		}
		for _, addr := range sortedKeys(pc.pexSent) {
			if len(msg.Dropped) == peer.MaxPEXPeers {
				break
			}
			if current[addr] == nil {
				if ap, err := netip.ParseAddrPort(addr); err == nil {
					msg.Dropped = append(msg.Dropped, ap)
				}
				delete(pc.pexSent, addr)
			}
		}
		if len(msg.Added)+len(msg.Dropped) > 0 {
			pc.queue(peer.Extended(uint8(pc.extPEX), msg.Encode()))
		}
	}
}

func (c *Client) pexFlags(pc *peerConn) byte {
	var f byte
	if pc.encrypted {
		f |= peer.PEXEncryption
	}
	if pc.has.Count() == c.t.NumPieces() {
		f |= peer.PEXSeed
	}
	if pc.outgoing {
		f |= peer.PEXReachable
	}
	return f
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
