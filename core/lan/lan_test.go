package lan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/mesh"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func TestBeacon(t *testing.T) {
	b := Beacon{Instance: Instance{1, 2, 3, 4, 5, 6, 7, 8}, Port: 6767}
	got, err := ParseBeacon(b.Encode())
	if err != nil || got != b {
		t.Fatalf("%+v %v", got, err)
	}
	bad := [][]byte{nil, b.Encode()[:10], append(b.Encode(), 0), []byte("XCN1\x01aaaaaaaa\x00\x01"),
		[]byte("BCN1\x02aaaaaaaa\x00\x01"), []byte("BCN1\x01aaaaaaaa\x00\x00")}
	for _, d := range bad {
		if _, err := ParseBeacon(d); err == nil {
			t.Errorf("%q accepted", d)
		}
	}
	inst, err := parseHello(hello(b.Instance))
	if err != nil || inst != b.Instance {
		t.Fatal("hello round trip")
	}
	if _, err := parseHello([]byte("beacon-link\x00\x02aaaaaaaa")); err == nil {
		t.Fatal("wrong hello version accepted")
	}
}

// host is one machine on an in-memory LAN.
func host(t *testing.T, mem *transport.Memory, ip string, ctx context.Context) *Links {
	t.Helper()
	l, err := Listen(Config{Stream: mem.From(ip), Multicast: mem.MulticastFrom(ip), Listen: ip + ":7000"})
	if err != nil {
		t.Fatal(err)
	}
	go l.Run(ctx)
	return l
}

func accept(t *testing.T, l *Links) transport.Link {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	k, err := l.Accept(ctx)
	if err != nil {
		t.Fatal("no link:", err)
	}
	return k
}

func TestDiscoveryLinks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mem := transport.NewMemory()
	a := host(t, mem, "10.0.0.1", ctx)
	b := host(t, mem, "10.0.0.2", ctx)
	if a.Port() != 7000 {
		t.Fatalf("port %d", a.Port())
	}
	ka, kb := accept(t, a), accept(t, b)
	// Both sides heard each other's beacon and dialed; exactly one connection
	// survives, the same one on both sides.
	time.Sleep(100 * time.Millisecond)
	a.mu.Lock()
	na := len(a.links)
	a.mu.Unlock()
	if na != 1 {
		t.Fatalf("a has %d links", na)
	}
	if live := drainExtra(a, ka); live != nil {
		ka = live
	}
	if live := drainExtra(b, kb); live != nil {
		kb = live
	}
	if err := ka.WriteFrame([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if f, err := kb.ReadFrame(); err != nil || string(f) != "ping" {
		t.Fatalf("%q %v", f, err)
	}
}

// drainExtra returns the link that survived if a duplicate was accepted too.
func drainExtra(l *Links, first transport.Link) transport.Link {
	select {
	case k := <-l.ready:
		return k
	default:
		return first
	}
}

func TestSimultaneousDial(t *testing.T) {
	for range 20 {
		ctx, cancel := context.WithCancel(context.Background())
		mem := transport.NewMemory()
		a, _ := Listen(Config{Stream: mem.From("10.0.0.1"), Listen: "10.0.0.1:7000"})
		b, _ := Listen(Config{Stream: mem.From("10.0.0.2"), Listen: "10.0.0.2:7000"})
		go a.Run(ctx)
		go b.Run(ctx)
		var wg sync.WaitGroup
		wg.Go(func() { a.Dial(ctx, "10.0.0.2:7000") })
		wg.Go(func() { b.Dial(ctx, "10.0.0.1:7000") })
		wg.Wait()
		// The accepting side's handshakes finish in their own goroutines;
		// wait for both sides to settle on the same connection.
		var ka, kb *lanLink
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			a.mu.Lock()
			b.mu.Lock()
			ka, kb = a.links[b.self], b.links[a.self]
			b.mu.Unlock()
			a.mu.Unlock()
			if ka != nil && kb != nil && ka.dialer == kb.dialer {
				break
			}
		}
		if ka == nil || kb == nil || ka.dialer != kb.dialer {
			t.Fatal("sides disagree on the surviving link")
		}
		go ka.WriteFrame([]byte("x"))
		if f, err := kb.ReadFrame(); err != nil || string(f) != "x" {
			t.Fatalf("surviving link broken: %v", err)
		}
		cancel()
	}
}

func TestHostileConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mem := transport.NewMemory()
	a := host(t, mem, "10.0.0.1", ctx)
	// A connection that never says hello is dropped after the timeout, and
	// one with a bad hello at once; neither becomes a link.
	silent, _ := mem.From("10.0.0.66").Dial(ctx, "10.0.0.1:7000")
	defer silent.Close()
	bad, _ := mem.From("10.0.0.66").Dial(ctx, "10.0.0.1:7000")
	bad.Write(bytes.Repeat([]byte{0xee}, helloSize))
	bad.SetReadDeadline(time.Now().Add(time.Second))
	io.ReadFull(bad, make([]byte, helloSize))
	if _, err := bad.Read(make([]byte, 1)); err == nil {
		t.Fatal("bad hello not cut off")
	}
	// The two unfinished handshakes from one IP use up its allowance.
	third, _ := mem.From("10.0.0.66").Dial(ctx, "10.0.0.1:7000")
	defer third.Close()
	third.SetReadDeadline(time.Now().Add(time.Second))
	select {
	case <-a.ready:
		t.Fatal("hostile connection became a link")
	case <-time.After(50 * time.Millisecond):
	}
	// Beacons from one sender are rate-limited.
	allowed := 0
	for range 100 {
		if a.allow(netipAddr("10.0.0.77")) {
			allowed++
		}
	}
	if allowed != beaconsPerMin {
		t.Fatalf("%d beacons allowed", allowed)
	}
}

// TestMeshOverLAN runs mesh nodes on LAN links: they find each other by
// multicast and chat, including an encrypted direct message.
func TestMeshOverLAN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mem := transport.NewMemory()
	got := make(chan mesh.Message, 16)
	var nodes []*mesh.Node
	for i := range 3 {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		links := host(t, mem, ip, ctx)
		id, _ := mesh.NewIdentity()
		n, err := mesh.New(mesh.Config{Identity: id, Nickname: fmt.Sprint("host", i), Links: links,
			OnMessage: func(m mesh.Message) { got <- m }})
		if err != nil {
			t.Fatal(err)
		}
		go n.Run(ctx)
		nodes = append(nodes, n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(nodes[0].Peers()) < 2 || len(nodes[2].Peers()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("nodes did not find each other")
		}
		time.Sleep(10 * time.Millisecond)
	}
	nodes[0].SendChannel("#lan", "hello lan")
	nodes[0].SendDirect(nodes[2].Fingerprint(), "just for you")
	seen := map[string]int{}
	timeout := time.After(5 * time.Second)
	for seen["hello lan"] < 2 || seen["just for you"] < 1 {
		select {
		case m := <-got:
			seen[m.Text]++
		case <-timeout:
			t.Fatalf("received %v", seen)
		}
	}
}

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func FuzzParseBeacon(f *testing.F) {
	f.Add(Beacon{Instance: Instance{1}, Port: 6767}.Encode())
	f.Add(hello(Instance{2}))
	f.Fuzz(func(t *testing.T, data []byte) {
		if b, err := ParseBeacon(data); err == nil && !bytes.Equal(b.Encode(), data) {
			t.Fatal("beacon did not round-trip")
		}
		if inst, err := parseHello(data); err == nil && !bytes.Equal(hello(inst), data) {
			t.Fatal("hello did not round-trip")
		}
	})
}
