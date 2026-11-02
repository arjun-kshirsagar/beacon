package engine

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/reputation"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func TestDialPriority(t *testing.T) {
	tor := seedDir(t, t.TempDir())
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	c.AddPeersFrom(SourcePEX, "8.8.8.1:1", "8.8.8.2:1")
	c.AddPeersFrom(SourceDHT, "8.8.8.3:1")
	c.AddPeersFrom(SourceTracker, "8.8.8.4:1")
	c.AddPeersFrom(SourceDHT, "8.8.8.2:1") // corroborates a PEX peer
	c.AddPeers("8.8.8.5:1")

	var got []string
	for len(c.queue) > 0 {
		got = append(got, c.next())
	}
	want := []string{"8.8.8.5:1", "8.8.8.4:1", "8.8.8.2:1", "8.8.8.3:1", "8.8.8.1:1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("dial order %v, want %v", got, want)
	}
}

func TestQueueCap(t *testing.T) {
	tor := seedDir(t, t.TempDir())
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	for i := range maxQueue + 500 {
		c.AddPeersFrom(SourcePEX, fmt.Sprintf("8.%d.%d.1:1", i/250, i%250))
	}
	if len(c.queue) != maxQueue {
		t.Fatalf("queue holds %d, cap %d", len(c.queue), maxQueue)
	}
	// A better-sourced peer still gets in, displacing a PEX one.
	c.AddPeersFrom(SourceTracker, "9.9.9.9:1")
	if len(c.queue) != maxQueue || c.queued["9.9.9.9:1"] == nil {
		t.Fatal("tracker peer not admitted to a queue full of PEX peers")
	}
	if c.next() != "9.9.9.9:1" {
		t.Fatal("tracker peer not dialed first")
	}
}

func TestAcceptAddr(t *testing.T) {
	tor := seedDir(t, t.TempDir())
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	tests := []struct {
		src  PeerSource
		addr string
		ok   bool
	}{
		{SourceDHT, "8.8.8.8:6881", true},
		{SourceDHT, "192.168.1.5:6881", false}, // strangers may not aim us at our LAN
		{SourcePEX, "10.0.0.1:80", false},
		{SourceLPD, "192.168.1.5:6881", true},
		{SourceTracker, "192.168.1.5:6881", true},
		{SourceTracker, "127.0.0.1:6881", false},
		{SourcePEX, "[fe80::1]:6881", false},
		{SourceDHT, "8.8.8.8:0", false},
		{SourceDHT, "seed.example:6881", false},
		{SourceManual, "seed.example:6881", true},
		{SourceManual, "127.0.0.1:6881", true},
	}
	for _, tt := range tests {
		if got := c.acceptAddr(tt.src, tt.addr); got != tt.ok {
			t.Errorf("%v %s: accepted=%v, want %v", tt.src, tt.addr, got, tt.ok)
		}
	}
}

// rawPeer dials a seeder from ip and completes the BitTorrent handshake.
func rawPeer(t *testing.T, mem *transport.Memory, ip, addr string, tor *torrent.Torrent) net.Conn {
	t.Helper()
	conn, err := mem.From(ip).Dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	peer.Handshake{InfoHash: tor.InfoHash, PeerID: NewPeerID()}.WriteTo(conn)
	if _, err := peer.ReadHandshake(conn); err != nil {
		t.Fatal(err)
	}
	return conn
}

// waitClosed reads until the connection fails.
func waitClosed(conn net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := peer.ReadMessage(conn, 1<<20); err != nil {
			return true
		}
	}
}

func TestPerIPLimit(t *testing.T) {
	mem := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	c := newClient(t, tor, src, mem)
	serve(t, c, mem, "10.0.0.1:6881")

	for range maxConnsPerIP {
		rawPeer(t, mem, "10.0.0.9", "10.0.0.1:6881", tor)
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.Stats().Peers < maxConnsPerIP && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	extra := rawPeer(t, mem, "10.0.0.9", "10.0.0.1:6881", tor)
	waitClosed(extra)
	if n := c.Stats().Peers; n != maxConnsPerIP {
		t.Fatalf("%d connections from one IP, limit %d", n, maxConnsPerIP)
	}
	// Another IP is unaffected.
	rawPeer(t, mem, "10.0.0.10", "10.0.0.1:6881", tor)
	for c.Stats().Peers < maxConnsPerIP+1 && time.Now().Before(deadline.Add(2*time.Second)) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := c.Stats().Peers; n != maxConnsPerIP+1 {
		t.Fatalf("second IP refused: %d peers", n)
	}
}

func TestFloodAndViolationsAffectReputation(t *testing.T) {
	mem := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	book := reputation.New(reputation.Config{})
	store, _ := OpenStorage(src, tor)
	t.Cleanup(func() { store.Close() })
	c, err := New(tor, store, Config{Transport: mem, Reputation: book})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, c, mem, "10.0.0.1:6881")

	// A burst of control messages beyond the bucket gets the peer dropped.
	conn := rawPeer(t, mem, "10.0.0.66", "10.0.0.1:6881", tor)
	go func() {
		for range tor.NumPieces() + 3*msgRate {
			if peer.WriteMessage(conn, &peer.Message{ID: peer.MsgNotInterested}) != nil {
				return
			}
		}
	}()
	if !waitClosed(conn) {
		t.Fatal("flooding peer not disconnected")
	}
	deadline := time.Now().Add(2 * time.Second)
	for book.Score("10.0.0.66") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s := book.Score("10.0.0.66"); s != -10 {
		t.Fatalf("score after flood = %d, want -10", s)
	}

	// A second offence, an invalid request, bans the peer; it cannot reconnect.
	conn = rawPeer(t, mem, "10.0.0.66", "10.0.0.1:6881", tor)
	peer.WriteMessage(conn, peer.Request(peer.MsgRequest, uint32(tor.NumPieces()), 0, BlockSize))
	waitClosed(conn)
	for !book.Banned("10.0.0.66") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !book.Banned("10.0.0.66") {
		t.Fatalf("not banned after flood and violation (score %d)", book.Score("10.0.0.66"))
	}
	again, _ := mem.From("10.0.0.66").Dial(context.Background(), "10.0.0.1:6881")
	defer again.Close()
	again.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.ReadHandshake(again); err == nil {
		t.Fatal("banned peer was answered")
	}
}

func TestSharedReputationAcrossTorrents(t *testing.T) {
	mem := transport.NewMemory()
	book := reputation.New(reputation.Config{})
	torA := seedDir(t, t.TempDir())
	torB := seedDir(t, t.TempDir())
	poisoner(t, mem, "evil", torA)

	newShared := func(tor *torrent.Torrent) *Client {
		store, _ := OpenStorage(t.TempDir(), tor)
		t.Cleanup(func() { store.Close() })
		c, err := New(tor, store, Config{Transport: mem, Reputation: book})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b := newShared(torA), newShared(torB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.Download(ctx, []string{"evil"})
	if !book.Banned("evil") {
		t.Fatal("poisoner not banned")
	}
	b.AddPeers("evil")
	if len(b.queue) != 0 {
		t.Fatal("a peer banned in one torrent was queued in another")
	}
}
