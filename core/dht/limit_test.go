package dht

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func TestQueryRateLimit(t *testing.T) {
	m, nodes := network(t, 1)
	conn, _ := m.ListenPacket("10.9.0.1:5000")
	defer conn.Close()
	dst, _ := m.ResolveAddr(context.Background(), nodes[0].Addr().String())
	me := string(RandomID().Bytes())
	for i := range 3 * queryBurst {
		conn.WriteTo(encodeQuery(fmt.Sprint(i), "ping", map[string]any{"id": me}), dst)
	}
	answered := 0
	buf := make([]byte, maxPacket)
	for {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, _, err := conn.ReadFrom(buf); err != nil {
			break
		}
		answered++
	}
	if answered < queryBurst || answered > queryBurst+2 {
		t.Fatalf("answered %d of %d queries, want about %d", answered, 3*queryBurst, queryBurst)
	}
	// Another IP still gets answers.
	if r := rawQuery(t, m, "10.9.0.2:5000", nodes[0].Addr().String(), "ping", map[string]any{"id": me}); r["y"] != "r" {
		t.Fatalf("other IP: %v", r)
	}
}

// TestLookupSubnetCap runs a lookup through a malicious node that answers every
// query with 20 IDs close to the target, all in one /24. The lookup may try at
// most maxPerSubnet of them.
func TestLookupSubnetCap(t *testing.T) {
	m := transport.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := RandomID()

	var hits atomic.Int32
	var sybils []Contact
	for i := range 20 {
		addr := fmt.Sprintf("10.66.0.%d:6881", i+1)
		sink, err := m.ListenPacket(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer sink.Close()
		go func() {
			buf := make([]byte, maxPacket)
			for {
				if _, _, err := sink.ReadFrom(buf); err != nil {
					return
				}
				hits.Add(1)
			}
		}()
		id := target
		id[19] ^= byte(i + 1)
		sybils = append(sybils, Contact{ID: id, Addr: mustAddrPort(addr)})
	}

	evil, _ := m.ListenPacket("10.77.0.1:6881")
	defer evil.Close()
	evilID := RandomID()
	go func() {
		buf := make([]byte, maxPacket)
		for {
			n, from, err := evil.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := parseMessage(buf[:n])
			if err != nil || q.Y != "q" {
				continue
			}
			evil.WriteTo(encodeResponse(q.T, map[string]any{
				"id": string(evilID[:]), "token": "t", "nodes": string(encodeNodes(sybils)),
			}), from)
		}
	}()

	victim, err := New(Config{Transport: m, Addr: "10.1.0.1:6881", QueryTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	go victim.Run(ctx)
	if err := victim.AddNode(ctx, "10.77.0.1:6881"); err != nil {
		t.Fatal(err)
	}
	victim.GetPeers(ctx, [20]byte(target))
	if h := hits.Load(); h > maxPerSubnet {
		t.Fatalf("lookup queried %d sybils in one /24, cap %d", h, maxPerSubnet)
	}
}

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
