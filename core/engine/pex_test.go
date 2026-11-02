package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// lastPEX drains pc's queue and returns the last PEX message in it.
func lastPEX(t *testing.T, pc *peerConn) (peer.PEX, bool) {
	t.Helper()
	var got peer.PEX
	found := false
	for {
		select {
		case m := <-pc.ctrl:
			id, body, err := peer.ParseExtended(m)
			if err != nil || int(id) != pc.extPEX {
				continue
			}
			if got, err = peer.ParsePEX(body); err != nil {
				t.Fatal(err)
			}
			found = true
		default:
			return got, found
		}
	}
}

func TestSendPEXDeltas(t *testing.T) {
	tor := seedDir(t, t.TempDir())
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	n := tor.NumPieces()
	listener := fakeConn(c, "10.0.0.1", peer.NewBitfield(n))
	listener.extPEX, listener.pexSent, listener.listenAddr = 9, map[string]bool{}, "10.0.0.1:6881"
	seed := fakeConn(c, "10.0.0.2", fullBitfield(n))
	seed.listenAddr, seed.outgoing, seed.encrypted = "10.0.0.2:6881", true, true
	unknown := fakeConn(c, "10.0.0.3", peer.NewBitfield(n)) // incoming, no listen port
	for _, pc := range []*peerConn{listener, seed, unknown} {
		c.conns[pc] = true
	}

	c.sendPEX()
	got, ok := lastPEX(t, listener)
	want := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:6881")}
	if !ok || len(got.Added) != 1 || got.Added[0] != want[0] || len(got.Dropped) != 0 {
		t.Fatalf("first message %+v (sent %v)", got, ok)
	}
	if f := got.Flags[0]; f != peer.PEXSeed|peer.PEXReachable|peer.PEXEncryption {
		t.Fatalf("flags %#x", f)
	}

	// Nothing changed: no message.
	c.sendPEX()
	if _, ok := lastPEX(t, listener); ok {
		t.Fatal("sent a PEX message with no changes")
	}

	// The seed leaves: it is reported dropped.
	delete(c.conns, seed)
	c.sendPEX()
	if got, ok = lastPEX(t, listener); !ok || len(got.Added) != 0 || len(got.Dropped) != 1 || got.Dropped[0] != want[0] {
		t.Fatalf("after drop: %+v", got)
	}
}

// startPeer runs a client on dir that listens on ip:6881, dials from ip, and
// knows only the given peers.
func startPeer(t *testing.T, mem *transport.Memory, tor *torrent.Torrent, allowPrivate bool, dir, ip string, peers ...string) *Client {
	t.Helper()
	store, err := OpenStorage(dir, tor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	c, err := New(tor, store, Config{Transport: mem.From(ip), ListenPort: 6881, AllowPrivatePeers: allowPrivate})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, c, mem, ip+":6881")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	c.AddPeers(peers...)
	return c
}

func knows(c *Client, addr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.known[addr]
	return ok
}

func TestPEXIntroducesPeers(t *testing.T) {
	defer func(d time.Duration) { pexInterval = d }(pexInterval)
	pexInterval = 50 * time.Millisecond

	tests := []struct {
		name                  string
		private, allowPrivate bool
		want                  bool
	}{
		{"public swarm", false, true, true},
		{"private addresses filtered", false, false, false},
		{"private torrent", true, true, false},
	}
	for _, tt := range tests {
		mem := transport.NewMemory()
		src := t.TempDir()
		tor := seedDir(t, src)
		tor.Private = tt.private

		startPeer(t, mem, tor, tt.allowPrivate, src, "10.0.0.1")
		b := startPeer(t, mem, tor, tt.allowPrivate, t.TempDir(), "10.0.0.2", "10.0.0.1:6881")
		c := startPeer(t, mem, tor, tt.allowPrivate, t.TempDir(), "10.0.0.3", "10.0.0.1:6881")

		// B and C only know the seeder; PEX from it may introduce them.
		deadline := time.Now().Add(time.Second)
		if tt.want {
			deadline = time.Now().Add(5 * time.Second)
		}
		for time.Now().Before(deadline) && !(knows(b, "10.0.0.3:6881") && knows(c, "10.0.0.2:6881")) {
			time.Sleep(10 * time.Millisecond)
		}
		if learned := knows(b, "10.0.0.3:6881") && knows(c, "10.0.0.2:6881"); learned != tt.want {
			t.Errorf("%s: peers learned each other via PEX = %v, want %v", tt.name, learned, tt.want)
		}
	}
}
