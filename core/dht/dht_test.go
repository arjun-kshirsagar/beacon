package dht

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func idWithPrefix(self ID, shared int, tail byte) ID {
	id := self
	// Flip bit `shared` so exactly `shared` leading bits match self.
	id[shared/8] ^= 0x80 >> (shared % 8)
	id[19] ^= tail
	return id
}

func TestPrefixLenAndDistance(t *testing.T) {
	var a ID
	b := a
	b[0] = 0x10
	if got := prefixLen(a, b); got != 3 {
		t.Errorf("prefixLen = %d, want 3", got)
	}
	if prefixLen(a, a) != idBits {
		t.Error("prefixLen of equal IDs")
	}
	c := a
	c[19] = 1
	if !closer(a, c, b) || closer(a, b, c) {
		t.Error("closer ordering wrong")
	}
}

func TestTableBucketLimits(t *testing.T) {
	now := time.Now()
	tb := table{self: RandomID()}

	// Fill one bucket from distinct subnets.
	for i := range K {
		c := Contact{ID: idWithPrefix(tb.self, 0, byte(i+1)), Addr: netip.MustParseAddrPort(fmt.Sprintf("10.%d.0.1:6881", i))}
		if !tb.seen(c, now) {
			t.Fatalf("contact %d rejected", i)
		}
	}
	extra := Contact{ID: idWithPrefix(tb.self, 0, 0xee), Addr: netip.MustParseAddrPort("10.99.0.1:6881")}
	if tb.seen(extra, now) {
		t.Fatal("full bucket accepted a new node while all nodes are healthy")
	}
	// A node that stops answering is replaced.
	victim := tb.buckets[0][3].ID
	tb.failed(victim)
	tb.failed(victim)
	if !tb.seen(extra, now) || tb.len() != K {
		t.Fatalf("failed node not replaced; len=%d", tb.len())
	}

	// At most maxPerSubnet nodes from one /24 per bucket.
	tb2 := table{self: RandomID()}
	for i := range maxPerSubnet + 2 {
		c := Contact{ID: idWithPrefix(tb2.self, 5, byte(i+1)), Addr: netip.MustParseAddrPort(fmt.Sprintf("192.168.1.%d:6881", i+1))}
		if got, want := tb2.seen(c, now), i < maxPerSubnet; got != want {
			t.Fatalf("subnet node %d: seen=%v, want %v", i, got, want)
		}
	}

	// A known ID cannot move to a new address.
	c := tb2.buckets[5][0].Contact
	moved := Contact{ID: c.ID, Addr: netip.MustParseAddrPort("172.16.0.1:1")}
	if tb2.seen(moved, now) || tb2.buckets[5][0].Addr != c.Addr {
		t.Fatal("node ID hijacked by a new address")
	}
	if tb2.seen(Contact{ID: tb2.self, Addr: c.Addr}, now) {
		t.Fatal("own ID added")
	}
}

func TestTableClosest(t *testing.T) {
	tb := table{self: RandomID()}
	var all []Contact
	for i := range 50 {
		c := Contact{ID: RandomID(), Addr: netip.MustParseAddrPort(fmt.Sprintf("10.%d.%d.1:6881", i/250, i%250))}
		if tb.seen(c, time.Now()) {
			all = append(all, c)
		}
	}
	target := RandomID()
	got := tb.closest(target, K)
	sortByDistance(all, target)
	if !slices.Equal(got, all[:K]) {
		t.Fatal("closest does not return the K nearest contacts")
	}
}

func TestCompactNodes(t *testing.T) {
	cs := []Contact{{ID: RandomID(), Addr: netip.MustParseAddrPort("1.2.3.4:6881")}}
	got, ok := decodeNodes(encodeNodes(cs))
	if !ok || !slices.Equal(got, cs) {
		t.Fatalf("round trip: %v", got)
	}
	if _, ok := decodeNodes(make([]byte, 25)); ok {
		t.Fatal("accepted truncated node list")
	}
	// Port 0 and unspecified addresses are dropped.
	if got, _ := decodeNodes(make([]byte, 26)); len(got) != 0 {
		t.Fatal("accepted 0.0.0.0:0")
	}
}

// network starts n nodes on an in-memory network; node i listens on 10.0.i.1.
func network(t *testing.T, size int) (*transport.Memory, []*Node) {
	t.Helper()
	m := transport.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	nodes := make([]*Node, size)
	done := make(chan struct{}, size)
	for i := range size {
		cfg := Config{Transport: m, Addr: fmt.Sprintf("10.0.%d.1:6881", i), QueryTimeout: 300 * time.Millisecond}
		if i > 0 {
			cfg.Bootstrap = []string{"10.0.0.1:6881"}
		}
		n, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = n
		go func() {
			n.Run(ctx)
			done <- struct{}{}
		}()
	}
	t.Cleanup(func() {
		cancel()
		for range size {
			<-done
		}
	})
	for _, n := range nodes[1:] {
		if err := n.Bootstrap(ctx); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
	}
	return m, nodes
}

func TestAnnounceAndGetPeers(t *testing.T) {
	_, nodes := network(t, 40)
	ctx := context.Background()
	ih := [20]byte(RandomID())

	if _, err := nodes[7].Announce(ctx, ih, 7000); err != nil {
		t.Fatal(err)
	}
	if _, err := nodes[21].Announce(ctx, ih, 7001); err != nil {
		t.Fatal(err)
	}
	peers, err := nodes[33].GetPeers(ctx, ih)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"10.0.7.1:7000", "10.0.21.1:7001"} {
		if !slices.Contains(peers, netip.MustParseAddrPort(want)) {
			t.Errorf("peer %s not found in %v", want, peers)
		}
	}
	if none, _ := nodes[33].GetPeers(ctx, [20]byte(RandomID())); len(none) != 0 {
		t.Errorf("unknown info-hash returned peers %v", none)
	}
}

// rawQuery sends one KRPC query from a bare socket and returns the reply.
func rawQuery(t *testing.T, m *transport.Memory, from, to string, q string, args map[string]any) map[string]any {
	t.Helper()
	conn, err := m.ListenPacket(from)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dst, _ := m.ResolveAddr(context.Background(), to)
	conn.WriteTo(encodeQuery("tx", q, args), dst)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, maxPacket)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	v, err := bencode.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func TestAnnounceTokenChecks(t *testing.T) {
	m, nodes := network(t, 2)
	target := nodes[0].Addr().String()
	ih := string(make([]byte, 20))
	me := string(RandomID().Bytes())

	resp := rawQuery(t, m, "10.9.0.1:5000", target, "get_peers", map[string]any{"id": me, "info_hash": ih})
	tok := resp["r"].(map[string]any)["token"].(string)

	// A token issued to one IP is useless from another.
	resp = rawQuery(t, m, "10.9.9.9:5000", target, "announce_peer", map[string]any{"id": me, "info_hash": ih, "port": 1234, "token": tok})
	if resp["y"] != "e" {
		t.Fatalf("stolen token accepted: %v", resp)
	}
	resp = rawQuery(t, m, "10.9.0.1:5000", target, "announce_peer", map[string]any{"id": me, "info_hash": ih, "port": 1234, "token": "forged"})
	if resp["y"] != "e" {
		t.Fatalf("forged token accepted: %v", resp)
	}
	resp = rawQuery(t, m, "10.9.0.1:5001", target, "announce_peer", map[string]any{"id": me, "info_hash": ih, "port": 1234, "token": tok})
	if resp["y"] != "r" {
		t.Fatalf("valid token rejected: %v", resp)
	}
	resp = rawQuery(t, m, "10.9.0.1:5000", target, "get_peers", map[string]any{"id": me, "info_hash": ih})
	values, _ := resp["r"].(map[string]any)["values"].([]any)
	if len(values) != 1 || values[0] != encodePeer(netip.MustParseAddrPort("10.9.0.1:1234")) {
		t.Fatalf("values %q", values)
	}

	resp = rawQuery(t, m, "10.9.0.1:5000", target, "bogus", map[string]any{"id": me})
	if resp["y"] != "e" {
		t.Fatalf("unknown method: %v", resp)
	}
	resp = rawQuery(t, m, "10.9.0.1:5000", target, "ping", map[string]any{})
	if resp["y"] != "e" {
		t.Fatalf("ping without id: %v", resp)
	}
}

func TestSpoofedResponseIgnored(t *testing.T) {
	m, nodes := network(t, 2)
	// A silent "node" that never answers; an attacker elsewhere guesses replies.
	silent, _ := m.ListenPacket("10.5.0.1:6881")
	defer silent.Close()
	attacker, _ := m.ListenPacket("10.6.0.1:6881")
	defer attacker.Close()
	go func() {
		buf := make([]byte, maxPacket)
		n, _, err := silent.ReadFrom(buf)
		if err != nil {
			return
		}
		q, err := parseMessage(buf[:n])
		if err != nil {
			return
		}
		// Correct transaction ID, wrong source address.
		attacker.WriteTo(encodeResponse(q.T, map[string]any{"id": string(RandomID().Bytes())}), nodes[0].Addr())
	}()
	if err := nodes[0].AddNode(context.Background(), "10.5.0.1:6881"); err != ErrTimeout {
		t.Fatalf("got %v, want timeout", err)
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add(encodeQuery("aa", "get_peers", map[string]any{"id": string(make([]byte, 20)), "info_hash": string(make([]byte, 20))}))
	f.Add(encodeResponse("aa", map[string]any{"id": string(make([]byte, 20)), "nodes": string(make([]byte, 52)), "values": []any{"abcdef"}}))
	f.Add(encodeError("aa", errGeneric, "oops"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseMessage(b)
		if err != nil {
			return
		}
		if len(m.T) == 0 || len(m.T) > maxTIDLen {
			t.Fatalf("bad tid %q", m.T)
		}
		if s, ok := m.R["nodes"].(string); ok {
			cs, _ := decodeNodes([]byte(s))
			for _, c := range cs {
				if !validAddr(c.Addr) {
					t.Fatalf("invalid node address %v", c.Addr)
				}
			}
		}
	})
}
