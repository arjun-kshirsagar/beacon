package dht

import (
	"crypto/rand"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"slices"
	"time"
)

const (
	// K is the bucket size and the number of closest nodes a lookup returns.
	K = 8
	// maxPerSubnet caps how many nodes from one /24 a bucket may hold, so a single
	// network cannot fill the table with Sybil identities.
	maxPerSubnet = 2
	// maxFailures is how many unanswered queries make a node replaceable.
	maxFailures = 2
	idBits      = 160
)

// ID is a 160-bit DHT node ID or info-hash.
type ID [20]byte

// RandomID returns a random ID from crypto/rand.
func RandomID() ID {
	var id ID
	rand.Read(id[:])
	return id
}

// prefixLen returns the number of leading bits a and b share.
func prefixLen(a, b ID) int {
	for i := range a {
		if x := a[i] ^ b[i]; x != 0 {
			return i*8 + bits.LeadingZeros8(x)
		}
	}
	return idBits
}

// closer reports whether a is closer to target than b by XOR distance.
func closer(target, a, b ID) bool {
	for i := range target {
		da, db := a[i]^target[i], b[i]^target[i]
		if da != db {
			return da < db
		}
	}
	return false
}

// Contact is a node's ID and address.
type Contact struct {
	ID   ID
	Addr netip.AddrPort
}

const compactNodeLen = 26

// encodeNodes returns the compact node info of IPv4 contacts.
func encodeNodes(cs []Contact) []byte {
	b := make([]byte, 0, len(cs)*compactNodeLen)
	for _, c := range cs {
		if !c.Addr.Addr().Is4() {
			continue
		}
		b = append(b, c.ID[:]...)
		ip := c.Addr.Addr().As4()
		b = append(b, ip[:]...)
		b = binary.BigEndian.AppendUint16(b, c.Addr.Port())
	}
	return b
}

// decodeNodes parses compact node info, skipping unusable entries.
func decodeNodes(b []byte) ([]Contact, bool) {
	if len(b)%compactNodeLen != 0 {
		return nil, false
	}
	var cs []Contact
	for ; len(b) > 0; b = b[compactNodeLen:] {
		var c Contact
		copy(c.ID[:], b[:20])
		c.Addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[20:24])), binary.BigEndian.Uint16(b[24:26]))
		if validAddr(c.Addr) {
			cs = append(cs, c)
		}
	}
	return cs, true
}

// encodePeer and decodePeer use the 6-byte compact peer format.
func encodePeer(a netip.AddrPort) string {
	ip := a.Addr().As4()
	return string(binary.BigEndian.AppendUint16(ip[:], a.Port()))
}

func decodePeer(s string) (netip.AddrPort, bool) {
	if len(s) != 6 {
		return netip.AddrPort{}, false
	}
	a := netip.AddrPortFrom(netip.AddrFrom4([4]byte([]byte(s[:4]))), binary.BigEndian.Uint16([]byte(s[4:])))
	return a, validAddr(a)
}

func validAddr(a netip.AddrPort) bool {
	ip := a.Addr()
	return a.Port() != 0 && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast()
}

type entry struct {
	Contact
	lastSeen time.Time
	failures int
}

// table is a Kademlia routing table: bucket i holds nodes whose IDs share
// exactly i leading bits with ours. It is not safe for concurrent use.
type table struct {
	self    ID
	buckets [idBits][]*entry
}

func subnet(a netip.AddrPort) [3]byte {
	ip := a.Addr().As4()
	return [3]byte(ip[:3])
}

// seen records that c answered or queried us. It returns whether c is in the
// table afterwards. Known IDs are never moved to a new address, which stops a
// node from hijacking another's slot.
func (t *table) seen(c Contact, now time.Time) bool {
	i := prefixLen(t.self, c.ID)
	if i == idBits || !validAddr(c.Addr) {
		return false
	}
	b := t.buckets[i]
	for _, e := range b {
		if e.ID == c.ID {
			if e.Addr != c.Addr {
				return false
			}
			e.lastSeen, e.failures = now, 0
			return true
		}
	}
	same := 0
	for _, e := range b {
		if subnet(e.Addr) == subnet(c.Addr) {
			same++
		}
	}
	if same >= maxPerSubnet {
		return false
	}
	ne := &entry{Contact: c, lastSeen: now}
	if len(b) < K {
		t.buckets[i] = append(b, ne)
		return true
	}
	// Full: only a node that stopped answering makes room. Long-lived nodes are
	// kept, which is both what Kademlia prescribes and what resists Sybils.
	for j, e := range b {
		if e.failures >= maxFailures {
			b[j] = ne
			return true
		}
	}
	return false
}

// failed records an unanswered query to id.
func (t *table) failed(id ID) {
	for _, e := range t.buckets[min(prefixLen(t.self, id), idBits-1)] {
		if e.ID == id {
			e.failures++
		}
	}
}

// closest returns up to n healthy contacts nearest target.
func (t *table) closest(target ID, n int) []Contact {
	var all []Contact
	for _, b := range t.buckets {
		for _, e := range b {
			if e.failures < maxFailures {
				all = append(all, e.Contact)
			}
		}
	}
	sortByDistance(all, target)
	return all[:min(n, len(all))]
}

func (t *table) len() int {
	n := 0
	for _, b := range t.buckets {
		n += len(b)
	}
	return n
}

// sortByDistance orders contacts nearest target first.
func sortByDistance(cs []Contact, target ID) {
	slices.SortFunc(cs, func(a, b Contact) int {
		switch {
		case closer(target, a.ID, b.ID):
			return -1
		case closer(target, b.ID, a.ID):
			return 1
		}
		return 0
	})
}

// Bytes returns the ID as a byte slice.
func (id ID) Bytes() []byte { return id[:] }
