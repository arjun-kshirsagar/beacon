package dht

import (
	"net/netip"
	"time"
)

const (
	queryRate    = 5  // queries per second we answer from one IP
	queryBurst   = 25 // and in a burst
	maxRateLimit = 4096
)

type bucket struct {
	tokens float64
	last   time.Time
}

// allowQuery applies a per-IP token bucket to incoming queries, so one host
// cannot use us to amplify traffic or burn our CPU on token HMACs.
func (n *Node) allowQuery(ip netip.Addr) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	b := n.queryRate[ip]
	if b == nil {
		if len(n.queryRate) >= maxRateLimit {
			clear(n.queryRate) // many senders; start over rather than grow
		}
		b = &bucket{tokens: queryBurst, last: now}
		n.queryRate[ip] = b
	}
	b.tokens = min(queryBurst, b.tokens+now.Sub(b.last).Seconds()*queryRate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
